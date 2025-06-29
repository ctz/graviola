# x86-64 CPU compatibility

This tracks the compatibility of Intel CPU families since 2004.  These are automatically characterised by the Intel SDE tool.
There are also a selection AMD CPUs that are characterised manually.

| Name | Supported? | AVX512-AES-GCM? | Details |
| --- | --- | --- | --- |
| AMD Zen 3 | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, ~~vaes~~ |
| AMD Zen 4 | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Pentium4 Prescott | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ~~ssse3~~, ~~vaes~~ |
| Intel Merom | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Penryn | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Nehalem | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Westmere | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Sandy Bridge | :white_circle: | :white_circle: | ~~adx~~, aes, avx, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Ivy Bridge | :white_circle: | :white_circle: | ~~adx~~, aes, avx, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Haswell | :white_circle: | :white_circle: | ~~adx~~, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Broadwell | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Saltwell | :white_circle: | :white_circle: | ~~adx~~, ~~aes~~, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, ~~pclmulqdq~~, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Silvermont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Goldmont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~ |
| Intel Goldmont Plus | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~ |
| Intel Tremont | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~ |
| Intel Snow Ridge | :white_circle: | :white_circle: | ~~adx~~, aes, ~~avx~~, ~~avx2~~, ~~avx512bw~~, ~~avx512f~~, ~~bmi1~~, ~~bmi2~~, pclmulqdq, sha, ssse3, ~~vaes~~ |
| Intel Skylake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Cannon Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, ~~vaes~~ |
| Intel Ice Lake | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Skylake server | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Cascade Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Cooper Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, ~~sha~~, ssse3, ~~vaes~~ |
| Intel Ice Lake server | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Tiger Lake | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Alder Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Meteor Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Raptor Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Sapphire Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Emerald Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Granite Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Granite Rapids (AVX10.1 / 256VL) | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Diamond Rapids | :large_blue_circle: | :large_blue_circle: | adx, aes, avx, avx2, avx512bw, avx512f, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Sierra Forest | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Arrow Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Lunar Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Panther Lake | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
| Intel Clearwater Forest | :large_blue_circle: | :white_circle: | adx, aes, avx, avx2, ~~avx512bw~~, ~~avx512f~~, bmi1, bmi2, pclmulqdq, sha, ssse3, vaes |
