# Threat model

Spoofing is mitigated by SPIFFE Verifiable Identity Document (SVID) identity and certificate-bound leases. Tampering is mitigated by Advanced Encryption Standard Galois/Counter Mode (AES-GCM) encryption and signed audit chains. Repudiation is mitigated by signatures. Disclosure is mitigated by taint scanning of modeled encodings. Denial of service is limited by bounded fail-closed code. Privilege escalation is limited by deny-by-default policies. Out of scope: paraphrase, steganography, screenshots, and timing channels.
