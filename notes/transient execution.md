---
tags:
  - pwn/microarchitecture/transient-execution
---
# Description
Transient execution occurs when a CPU predictively (speculatively) runs instructions beyond the current instruction to minimize program runtime. While this speculation's results are not committed to the architectural state if it is incorrectly predicted, the effects are commonly observed in the microarchitectural state.