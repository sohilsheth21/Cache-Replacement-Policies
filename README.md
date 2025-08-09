# Cache-Replacement-Policies

This project implements the Dead Block Replacement Policy and an improved version on the ChampSim simulator. These policies were evaluated against SPEC benchmarks and compared to existing policies such as LRU, Ship, Hawkeye, and SRRIP.

**Proposed Policy:** (Building upon DeadBlock replacement policy)
- **Dead On Arrival (DOA):** Identifying early cache pollution
  - DOA Blocks: Inserted into cache but never reused
               Tag based mechanism for tracking evictions without cache hit
  - Eviction Strategy: Maintaining DOA score for each PC and evicting blocks with high DOA contribution

- **Dirty vs Clean Block Eviction:** Dirty blocks include a writeback cost on eviction.
  - Mechanism: Add a dirty status bit along with a reuse score

- **Eviction Strategy:** Blocks with low cost (clean + low reuse) are prioritized for eviction. 
Eviction preference hierarchy:
  - DOA-tagged clean blocks
  - Non-recent clean blocks
  - Dirty blocks

Simulated on ChampSim with 200M warm up instructions and 1B simulation instruction.

- **How To simulate:**
  - Git Clone the [ChampSim repository](https://github.com/ChampSim/ChampSim).
  - Add the code in the replacement directory in ChampSim folder. (/replacement/deadblock/add_your_code_and_header)
  - Include the benchmarks and run the sbatch script.




