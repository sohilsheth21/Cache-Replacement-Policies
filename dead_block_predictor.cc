#include "dead_block_predictor.h" 

#include <algorithm>
#include <cassert>
#include <random>

dead_block_predictor::dead_block_predictor(CACHE* cache)
    : replacement(cache), NUM_SET(cache->NUM_SET), NUM_WAY(cache->NUM_WAY),
      sampler(SAMPLER_SET_FACTOR * static_cast<std::size_t>(NUM_WAY)),
      predictions(static_cast<std::size_t>(NUM_SET * NUM_WAY), false),
      pred_tables(NUM_PRED_TABLES, std::array<champsim::msl::fwcounter<2>, PRED_TABLE_SIZE>{})
{
    std::generate_n(std::back_inserter(sampler_sets), SAMPLER_SET_FACTOR, std::knuth_b{1});
    std::sort(std::begin(sampler_sets), std::end(sampler_sets));
    for (auto& set : sampler_sets) {
        set %= NUM_SET;
    }
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

    for (long way = 0; way < NUM_WAY; ++way) {
        if (get_prediction(set, way)) {
            return way;
        }
    }

    for (long way = 0; way < NUM_WAY; ++way) {
        if (current_set[way].valid) {
            return way;
        }
    }

    assert(false && "No valid victim found");
    return 0;
}

void dead_block_predictor::update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                                    champsim::address victim_addr, access_type type, uint8_t hit)
{
    auto idx1 = hash_trace1(ip);
    auto idx2 = hash_trace2(ip);
    auto idx3 = hash_trace3(ip);

    auto s_idx = std::find(std::begin(sampler_sets), std::end(sampler_sets), set);
    if (s_idx != std::end(sampler_sets)) {
        auto s_set_begin = std::next(std::begin(sampler), std::distance(std::begin(sampler_sets), s_idx) * NUM_WAY);
        auto s_set_end = std::next(s_set_begin, NUM_WAY);

        auto match = std::find_if(s_set_begin, s_set_end, [ip](const SamplerEntry& x) {
            return x.valid && x.ip == ip;
        });
        if (match == s_set_end) {
            match = std::min_element(s_set_begin, s_set_end, [](const SamplerEntry& x, const SamplerEntry& y) {
                return x.last_used < y.last_used;
            });
            if (match->valid && match->predicted_dead) {
                pred_tables[0][hash_trace1(match->ip)]++;
                pred_tables[1][hash_trace2(match->ip)]++;
                pred_tables[2][hash_trace3(match->ip)]++;
            }
            match->valid = true;
            match->ip = ip;
            match->last_used = access_count++;
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
        predictions[static_cast<std::size_t>(set * NUM_WAY + way)] = (sum_counters >= PRED_THRESHOLD);
    } else {
        predictions[static_cast<std::size_t>(set * NUM_WAY + way)] = false;
    }

    access_count++;
}