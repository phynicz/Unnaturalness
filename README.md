# Unnaturalness

This is the artifact repository for the paper "From base cases to backdoors: An Empirical Study of Unnatural Crypto-API Misuse". This repository contains the following:

### app_dataset

+ This contains the dataset of (i) mobile-IoT and (ii) non-IoT apps analyzed in this work.

### case study

This directory includes: 
+ Contains two directories of (i) qwq32b model and (ii) claude_sonnet_4_5. They both include scripts and results for all 5 backdoors analyzed for the case study.

### crypto-tools analysis

This directory includes the following:

+ Contains a minimal working apks misuse directory for both restrictive and flexible invocations used in the crypto-tools experiment.
+ Decompiler fidelity results show that developers can indeed write code seen in our results. 
+ Detailed Results from testing crypto-detector tools with odd/unnatural misuse patterns.

### qualitative analysis data

This directory includes the following:

+ Taxonomies of both restrictive and flexible invocation and code snippers.
+ Includes all invocations of `Cipher.getInstance` invocation before sampling.
+ Includes all invocations of `checkServerTrusted` invocation before sampling.
+ Includes sampled invocation for `Cipher.getInstance`, `checkServerTrusted`, `hostnameVerifier`, `SecretKeySpec`.
+ Flexible Invocations Taxonomy - Code Snippets.
+ Images of graphs of both SecretKeySpec and HostnameVerifier.
+ Number of Restrictive & Flexible Invocation Samples.

### Scripts

This directory includes the following:

+ Script decompiling mobile apps and extracting/findings relevant cryptographic-APIs.
+ All other scripts are used to generate the ASTs for each respective crypto-API, extract the arguments/parameters and compute the complexity score.


