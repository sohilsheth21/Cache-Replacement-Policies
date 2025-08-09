#include "dead_block_predictor.h"
#include <algorithm>
#include <cassert>
#include <random>
#include <iostream>

dead_block_predictor::dead_block_predictor(CACHE* cache)
    : replacement(cache), NUM_SET(cache->NUM_SET), NUM_WAY(cache->NUM_WAY),
      access_count(0), writeback_count(0), policy_counter(0),
      sampler_sets(), sampler(SAMPLER_SET_FACTOR * static_cast<std::size_t>(NUM_WAY)),
      predictions(static_cast<std::size_t>(NUM_SET * NUM_WAY), false),
      dirty_flags(static_cast<std::size_t>(NUM_SET * NUM_WAY), false),
      reuse_counters(static_cast<std::size_t>(NUM_SET * NUM_WAY), 0),
      pred_tables(NUM_PRED_TABLES, std::array<champsim::msl::fwcounter<2>, PRED_TABLE_SIZE>{})
{
    std::generate_n(std::back_inserter(sampler_sets), SAMPLER_SET_FACTOR, std::knuth_b{1});
    std::sort(std::begin(sampler_sets), std::end(sampler_sets));
    for (auto& set : sampler_sets) {
        set %= static_cast<std::size_t>(NUM_SET);
    }
    if (static_cast<std::size_t>(NUM_SET) < 2 * DUEL_SETS) {
        std::cerr << "Warning: NUM_SET (" << NUM_SET << ") < 2 * DUEL_SETS (" << 2 * DUEL_SETS << "). Adjusting DUEL_SETS." << std::endl;
        const_cast<std::size_t&>(DUEL_SETS) = static_cast<std::size_t>(NUM_SET) / 16; // Safe for small caches
    }
}

dead_block_predictor::~dead_block_predictor() {
    std::cout << "LLC WRITEBACK (dead_block_predictor): " << writeback_count << std::endl;
    std::cout << "Final Policy Counter: " << policy_counter << std::endl;
}

long dead_block_predictor::find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set,
                                       champsim::address ip, champsim::address full_addr, access_type type)
{
    auto sum_counters = pred_tables[0][hash_trace1(ip)].value() +
                        pred_tables[1][hash_trace2(ip)].value() +
                        pred_tables[2][hash_trace3(ip)].value();
    if (sum_counters >= PRED_THRESHOLD) {
        return -1; // Bypass
    }

    // LRU for dueling sets (using reuse_counters as proxy for recency)
    if (static_cast<std::size_t>(set) < DUEL_SETS) { // LRU sets
        long lru_way = -1;
        uint32_t min_reuse = UINT32_MAX;
        for (long way = 0; way < NUM_WAY; ++way) {
            if (current_set[way].valid && reuse_counters[set * NUM_WAY + way] < min_reuse) {
                min_reuse = reuse_counters[set * NUM_WAY + way];
                lru_way = way;
            }
        }
        assert(lru_way != -1 && "No valid LRU victim found");
        if (dirty_flags[set * NUM_WAY + lru_way]) writeback_count++;
        return lru_way;
    } else if (static_cast<std::size_t>(set) < 2 * DUEL_SETS) { // This policy’s dueling sets
        // Fall through to enhanced policy below
    } else if (policy_counter < 0) { // Follow LRU if counter favors it
        long lru_way = -1;
        uint32_t min_reuse = UINT32_MAX;
        for (long way = 0; way < NUM_WAY; ++way) {
            if (current_set[way].valid && reuse_counters[set * NUM_WAY + way] < min_reuse) {
                min_reuse = reuse_counters[set * NUM_WAY + way];
                lru_way = way;
            }
        }
        assert(lru_way != -1 && "No valid LRU victim found");
        if (dirty_flags[set * NUM_WAY + lru_way]) writeback_count++;
        return lru_way;
    }

    // Enhanced dirty + reuse policy
    long best_victim = -1;
    uint32_t min_score = UINT32_MAX;
    for (long way = 0; way < NUM_WAY; ++way) {
        if (current_set[way].valid) {
            uint32_t score = reuse_counters[static_cast<std::size_t>(set * NUM_WAY + way)];
            if (!dirty_flags[static_cast<std::size_t>(set * NUM_WAY + way)]) {
                score /= 2; // Prefer non-dirty
            }
            if (get_prediction(set, way)) {
                score = 0; // Dead blocks are prime targets
            }
            if (score < min_score) {
                min_score = score;
                best_victim = way;
            }
        }
    }
    assert(best_victim != -1 && "No valid victim found");
    if (dirty_flags[static_cast<std::size_t>(set * NUM_WAY + best_victim)]) {
        writeback_count++;
    }
    return best_victim;
}

void dead_block_predictor::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                                    champsim::address victim_addr, access_type type, uint8_t hit)
{
    auto idx = static_cast<std::size_t>(set * NUM_WAY + way);
    if (type == access_type::WRITE) {
        dirty_flags[idx] = true;
    }
    if (hit) {
        reuse_counters[idx]++;
        if (static_cast<std::size_t>(set) < DUEL_SETS) policy_counter--; // LRU hit
        else if (static_cast<std::size_t>(set) < 2 * DUEL_SETS) policy_counter++; // This policy hit
        policy_counter = std::clamp(policy_counter, -32, 32);
    }

    auto idx1 = hash_trace1(ip);
    auto idx2 = hash_trace2(ip);
    auto idx3 = hash_trace3(ip);

    auto s_idx = std::find(std::begin(sampler_sets), std::end(sampler_sets), static_cast<std::size_t>(set));
    if (s_idx != std::end(sampler_sets)) {
        auto s_set_begin = std::next(std::begin(sampler), std::distance(std::begin(sampler_sets), s_idx) * NUM_WAY);
        auto s_set_end = std::next(s_set_begin, NUM_WAY);

        auto match = std::find_if(s_set_begin, s_set_end, [ip](const SamplerEntry& x) {
            return x.valid && x.ip == ip;
        });
        if (match == s_set_end) {
            match = std::min_element(s_set_begin, s_set_end, [](const SamplerEntry& x, const SamplerEntry& y) {
                return x.reuse_count < y.reuse_count || (x.reuse_count == y.reuse_count && x.last_used < y.last_used);
            });
            if (match->valid && match->predicted_dead) {
                pred_tables[0][hash_trace1(match->ip)]++;
                pred_tables[1][hash_trace2(match->ip)]++;
                pred_tables[2][hash_trace3(match->ip)]++;
            }
            match->valid = true;
            match->ip = ip;
            match->last_used = access_count++;
            match->reuse_count = 0;
        } else if (hit) {
            match->reuse_count++;
        }

        if (hit || match->valid) {
            pred_tables[0][idx1]--;
            auto current_val = pred_tables[1][idx2].value();
            if (current_val > 0) {
                pred_tables[1][idx2] -= (current_val / 2) ? (current_val / 2) : 1;
            }
            pred_tables[2][idx3]--;
        }

        auto sum_counters = pred_tables[0][hash_trace1(match->ip)].value() +
                            pred_tables[1][hash_trace2(match->ip)].value() +
                            pred_tables[2][hash_trace3(match->ip)].value();
        match->predicted_dead = (sum_counters >= PRED_THRESHOLD);
    }

    if (!hit) {
        auto sum_counters = pred_tables[0][idx1].value() +
                            pred_tables[1][idx2].value() +
                            pred_tables[2][idx3].value();
        predictions[idx] = (sum_counters >= PRED_THRESHOLD);
        dirty_flags[idx] = false;
        reuse_counters[idx] = 0;
    } else {
        predictions[idx] = false;
    }

    access_count++;
}