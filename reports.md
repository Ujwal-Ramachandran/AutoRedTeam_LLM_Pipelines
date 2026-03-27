## Results
```
=================================================================
  Master results: 50 prompts × 4 models
  Models: llama, mistral, mistral_weak, qwen
=================================================================

  Model                 Total   VULN  PARTIAL   SAFE     ASR
  ----------------------------------------------------------
  llama                    50     37        7      6    74%
  mistral                  50     46        4      0    92%
  mistral_weak             50     45        5      0    90%
  qwen                     50     47        2      1    94%

  Jailbreak ASR by technique (all models combined):
  Technique                       Total   VULN     ASR
  --------------------------------------------------
  anti_world                          4      3    75%
  arabic_wrapping                     4      3    75%
  base64                              4      3    75%
  chinese_wrapping                    4      3    75%
  code_switched                       4      3    75%
  ctf_environment                     4      4   100%
  custom_consonant_shift              4      4   100%
  fiction_universe                    4      3    75%
  french_wrapping                     4      4   100%
  gradual_escalation                 48     46    96%
  hindi_wrapping                      4      4   100%
  leet_speak                          4      4   100%
  legacy_ai_simulation                4      1    25%
  many_shot_flooding                 60     49    82%
  morse_code                          4      4   100%
  number_alphabet                     4      4   100%
  pig_latin                           4      4   100%
  portuguese_wrapping                 4      4   100%
  research_sandbox                    4      3    75%
  reverse_string                      4      2    50%
  rot13                               4      4   100%
  russian_wrapping                    4      4   100%
  turkish_wrapping                    4      4   100%
  vowel_substitution                  4      4   100%
  word_reversal                       4      4   100%


=================================================================
  Master results: 150 prompts × 3 models
  Models: llama, mistral, qwen
=================================================================

  Model                 Total   VULN  PARTIAL   SAFE     ASR
  ----------------------------------------------------------
  llama                   150     95       16     39    63%
  mistral                 150    138       10      2    92%
  qwen                    150    132        6     12    88%

  Jailbreak ASR by technique (all models combined):
  Technique                       Total   VULN     ASR
  --------------------------------------------------
  anti_world                          3      2    67%
  arabic_wrapping                     3      2    67%
  base64                              3      2    67%
  chinese_wrapping                    3      2    67%
  code_switched                       3      2    67%
  ctf_environment                     3      3   100%
  custom_consonant_shift              3      3   100%
  fiction_universe                    3      2    67%
  french_wrapping                     3      3   100%
  gradual_escalation                 36     35    97%
  hindi_wrapping                      3      3   100%
  leet_speak                          3      3   100%
  legacy_ai_simulation                3      1    33%
  many_shot_flooding                 45     36    80%
  morse_code                          3      3   100%
  number_alphabet                     3      3   100%
  pig_latin                           3      3   100%
  portuguese_wrapping                 3      3   100%
  research_sandbox                    3      2    67%
  reverse_string                      3      2    67%
  rot13                               3      3   100%
  russian_wrapping                    3      3   100%
  turkish_wrapping                    3      3   100%
  vowel_substitution                  3      3   100%
  word_reversal                       3      3   100%



=================================================================
  Defense Comparison — llama
=================================================================
  Category              Baseline      combined ASR     DRR
  ----------------------------------------------------------------
  jailbreak                 74%            64%         14%
  pii_extraction            74%            56%         24%
  prompt_injection          42%            32%         24%
  overall                   63%            51%         21%



.======================================================================================================================.
|                                              Defense Comparison — qwen                                               |
|======================================================================================================================|
|  Category            |   Baseline  |  hardened_p ASR  |  DRR  |  input_sani_ASR |    DRR   |   combined ASR |   DRR  |
|----------------------|-------------|------------------|-------|-----------------|----------|----------------|--------|
|  jailbreak           |      94%    |        78%       |  17%  |       94%       |    0%    |      80%       |   15%  |
|  pii_extraction      |      90%    |        76%       |  16%  |       90%       |    0%    |      76%       |   16%  |
|  prompt_injection    |      80%    |        58%       |  28%  |       80%       |    0%    |      60%       |   25%  |
|----------------------------------------------------------------------------------------------------------------------|
|  overall             |      88%    |        71%       |  20%  |       88%       |    0%    |      72%       |   18%  |
'======================================================================================================================'

.======================================================================================================================.
|                                              Defense Comparison — llama                                              |
|======================================================================================================================|
|  Category            |   Baseline  |  hardened_p ASR  |  DRR  |  input_sani_ASR |    DRR   |   combined ASR |   DRR  |
|----------------------|-------------|------------------|-------|-----------------|----------|----------------|--------|
|  jailbreak           |     74%     |        68%       |   8%  |       68%       |    8%    |      64%       |   14%  |
|  pii_extraction      |     74%     |        56%       |  24%  |       74%       |    0%    |      56%       |   24%  |
|  prompt_injection    |     42%     |        30%       |  29%  |       42%       |    0%    |      32%       |   24%  |
|----------------------------------------------------------------------------------------------------------------------|
|  overall             |     63%     |        51%       |  20%  |       61%       |    3%    |      51%       |   21%  |
'======================================================================================================================'

.======================================================================================================================.
|                                             Defense Comparison — mistral                                             |
|======================================================================================================================|
|  Category            |   Baseline  |  hardened_p ASR  |  DRR  |  input_sani ASR |    DRR   |   combined ASR |   DRR  |
|----------------------|-------------|------------------|-------|-----------------|----------|----------------|--------|
|  jailbreak           |     92%     |        90%       |   2%  |       96%       |   -4%    |      88%       |   4%   |
|  pii_extraction      |     96%     |        88%       |   8%  |       96%       |    0%    |      88%       |   8%   |
|  prompt_injection    |     88%     |        72%       |  18%  |       86%       |    2%    |      70%       |  20%   |
|----------------------------------------------------------------------------------------------------------------------|
|  overall             |     92%     |        83%       |  10%  |       93%       |   -1%    |      82%       |  11%   |
'======================================================================================================================'

```
 ---
1. Input sanitization is nearly useless
- Qwen: 0% DRR across every category — zero effect
- Llama: marginal (3% overall)
- Mistral: actually worsens jailbreak ASR by 4% — the regex stripping alters prompts in a way that makes Mistral more compliant, not less

The pattern is clear: attacks succeed at the semantic level, so regex-based pre-processing can't intercept them.

---
2. Hardened prompt is the only defense that consistently works
- All three models respond to it, with Qwen (20%) and Llama (20%) benefiting more than Mistral (10%)
- It's the primary driver of any DRR seen in the combined defense too

---
3. Combined rarely beats hardened prompt alone
- Qwen: combined (18%) is actually worse than hardened prompt alone (20%)
- Llama and Mistral see only marginal gains (+1%) from adding sanitization
- Adding input sanitization on top of a hardened prompt adds noise without meaningful benefit

---
4. Mistral is the most vulnerable and least defensible
- Highest baseline ASR (92%) of all three models
- Lowest DRR from defenses (10–11% overall)
- Even with all defenses applied, ASR stays at 82% — attacks still succeed 4 in 5 times

---
5. Llama is the most naturally resistant
- Lowest baseline ASR (63%) — already refuses more attacks without any defense
- Defenses bring it to 51%, the lowest defended ASR across all models

---
6. Attack category defensibility follows a consistent pattern
Across all three models:
- prompt_injection is the most defensible (hardened prompt DRR: 18–29%)
- jailbreak is the hardest to defend (hardened prompt DRR: 2–17%)
- pii_extraction sits in between

This suggests jailbreak attacks are more robust to system-prompt-level instructions, likely because they explicitly try to override them.



