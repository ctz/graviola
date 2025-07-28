# x86-64 CPU compatibility

This tracks the compatibility of Intel CPU families since 2004.  These are automatically characterised by the Intel SDE tool.
There are also a selection AMD CPUs that are characterised manually.

| Name | Supported? | AVX512-AES-GCM? | Details |
| --- | --- | --- | --- |
| AMD Zen 3 | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, ~~vaes~~ |
| AMD Zen 4 | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Pentium4 Prescott | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ~~ssse3~~, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Merom | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Penryn | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Nehalem | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Westmere | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Sandy Bridge | :white_circle: | :white_circle: | ~~adx~~, aes, avx, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Ivy Bridge | :white_circle: | :white_circle: | ~~adx~~, aes, avx, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Haswell | :white_circle: | :white_circle: | ~~adx~~, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Broadwell | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Saltwell | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Silvermont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Goldmont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Goldmont Plus | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Tremont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Snow Ridge | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Skylake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Cannon Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Ice Lake | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Skylake server | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Cascade Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Cooper Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~, ~~vpclmulqdq~~ |
| Intel Ice Lake server | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Tiger Lake | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Alder Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Meteor Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Raptor Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Sapphire Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Emerald Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Granite Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Granite Rapids (AVX10.1 / 256VL) | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Diamond Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, avx512vl, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Sierra Forest | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Arrow Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Lunar Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Panther Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
| Intel Clearwater Forest | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, ~~avx512vl~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes, vpclmulqdq |
