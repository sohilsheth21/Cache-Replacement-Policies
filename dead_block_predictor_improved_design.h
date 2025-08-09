#ifndef REPLACEMENT_DEAD_BLOCK_PREDICTOR_H
#define REPLACEMENT_DEAD_BLOCK_PREDICTOR_H

#include <array>
#include <vector>
#include <cstdint>

#include "cache.h"
#include "modules.h"
#include "msl/bits.h"
#include "msl/fwcounter.h"

struct dead_block_predictor : public champsim::modules::replacement {
private:
    inline bool get_prediction(long set, long way) {
        return predictions.at(static_cast<std::size_t>(set * NUM_WAY + way));
    }

    inline std::size_t hash_trace1(champsim::address ip) {
        return ip.slice_lower<champsim::data::bits{32}>().to<std::size_t>() % PRED_TABLE_SIZE;
    }

    inline std::size_t hash_trace2(champsim::address ip) {
        return (ip.slice_lower<champsim::data::bits{32}>().to<std::size_t>() * 17 + 0xdead) % PRED_TABLE_SIZE;
    }

    inline std::size_t hash_trace3(champsim::address ip) {
        return (ip.slice_lower<champsim::data::bits{32}>().to<std::size_t>() * 31 + 0xbeef) % PRED_TABLE_SIZE;
    }

public:
    static constexpr std::size_t SAMPLER_SET_FACTOR = 55;
    static constexpr std::size_t PRED_TABLE_SIZE = 4096;
    static constexpr unsigned PRED_TABLE_MAX = 3;
    static constexpr unsigned PRED_THRESHOLD = 8;
    static constexpr std::size_t NUM_PRED_TABLES = 3;
    static constexpr std::size_t DUEL_SETS = 128; // Adjust if NUM_SET < 256

    class SamplerEntry {
    public:
        bool valid = false;
        champsim::address ip{};
        bool predicted_dead = false;
        uint64_t last_used = 0;
        uint32_t reuse_count = 0; // Track reuse in sampler
    };

    long NUM_SET, NUM_WAY;
    uint64_t access_count = 0;
    uint64_t writeback_count = 0;
    int policy_counter = 0; // -32 to 32, positive favors this policy

    std::vector<std::size_t> sampler_sets;
    std::vector<SamplerEntry> sampler;
    std::vector<bool> predictions;
    std::vector<bool> dirty_flags;
    std::vector<uint32_t> reuse_counters; // Per-block reuse tracking

    std::vector<std::array<champsim::msl::fwcounter<2>, PRED_TABLE_SIZE>> pred_tables;

    explicit dead_block_predictor(CACHE* cache);
    ~dead_block_predictor();

    long find_victim(uint32_t triggering_cpu, uint64_t instr_id, long set, const champsim::cache_block* current_set, champsim::address ip,
                     champsim::address full_addr, access_type type);
    void update_replacement_state(uint32_t triggering_cpu, long set, long way, champsim::address full_addr, champsim::address ip,
                                  champsim::address victim_addr, access_type type, uint8_t hit);
};

#endif