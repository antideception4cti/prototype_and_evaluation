# Full-corpus run summary

`has_AD` = share reaching the anti-deception floor (`weak_proxy`+). Strong anti-deception claims require `sequence_supported`, `strong_proxy`, or `testbed_grounded`; none occur in the real corpora below.

| dataset | sessions | none | weak_context | observed_marker | weak_proxy | strong AD | has_AD |
|---|---:|---:|---:|---:|---:|---:|---:|
| cyberlab | 24,896,360 | 24,624,260 (98.91%) | 269,473 (1.08%) | 74 (0.00%) | 2,553 (0.010%) | 0 | 2,553 (0.010%) |
| GlobalSSH | 47,569 | 40,004 (84.10%) | 7,482 (15.73%) | 0 (0.00%) | 83 (0.174%) | 0 | 83 (0.174%) |
| pandacap_disk | 63 | 63 (100.00%) | 0 | 0 | 0 | 0 | 0 (0.000%) |

## PANDAcap forward-CTI classes

| class | sessions |
|---|---:|
| Brute-force/login only | 29 |
| Outlaw/Dota persistence | 27 |
| ZIGAZAGA loader | 5 |
| Recon/commands only | 2 |

## Bidirectional signal streams

| dataset | attack_interaction | baseline | combined |
|---|---:|---:|---:|
| cyberlab | 9,636,617 | 15,257,190 | 2,553 |
| GlobalSSH | 26,793 | 20,693 | 83 |
| pandacap_disk | 34 | 29 | 0 |

## Notes

One CyberLab compressed input was truncated; the resilient runner processed the readable prefix, recorded the issue, and continued. Raw corpora and local paths are intentionally not included in this repository.
