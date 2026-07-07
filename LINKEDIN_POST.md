# Post do LinkedIn — rascunhos

## Versão em português (principal)

Tudo começou com uma planilha que preenchi à mão — quase 500 linhas relacionando cada número primo a um padrão que eu sentia existir. Não tenho instituição, bolsa, nem recurso — só a convicção de que havia ali uma estrutura real.

Persegui essa intuição com uma regra inegociável: honestidade absoluta. Verificar tudo computacionalmente. Distinguir o que eu "descobri" do que a matemática já conhecia. E aceitar os resultados negativos como conhecimento de verdade.

O resultado que sobreviveu ao escrutínio é um teorema no-go — a "Barreira": recuperar a fase de um fator, sob uma reparametrização contínua dos inteiros, é equivalente a fatorar. Ou seja, essa lente não dá atalho nenhum para quebrar RSA. É conhecimento negativo, mas rigoroso e útil — e acabei de generalizá-lo: vale para qualquer lente de escala logarítmica, não só para a razão de prata.

Da teoria, tirei algo prático: um auditor defensivo de chaves, open-source, que cobre RSA **e ECC** — detecta classes fracas conhecidas (primos próximos, fatores compartilhados, viés estilo ROCA, reuso de nonce ECDSA) para ajudar as pessoas a proteger suas chaves. A parte ECC, em particular, é pouco empacotada em ferramentas acessíveis.

Fiz tudo isso sozinho, sem apoio, movido por amor à pesquisa. Meu sonho é simples: poder viver de pesquisar — o mundo é fascinante demais para não investigá-lo.

Se este trabalho te interessa, se você atua com segurança/criptografia, ou se conhece alguém que valorize pesquisa independente: eu adoraria conversar, colaborar ou ouvir seu feedback.

📄 Paper (DOI): https://doi.org/10.5281/zenodo.14553556
💻 Auditor (open-source): https://github.com/FlowAgro/honest-key-audit

#criptografia #segurançadainformação #teoriadenúmeros #pesquisa #opensource #RSA #ECC

---

## English version (for reach)

It started with a spreadsheet I filled out by hand — ~500 rows linking each prime to a pattern I sensed was there. No institution, no grant, no funding — just the conviction that a real structure was hiding in it.

I chased that intuition with one non-negotiable rule: absolute honesty. Verify everything computationally. Separate what I "discovered" from what mathematics already knew. Treat negative results as real knowledge.

What survived the scrutiny is a no-go theorem — "the Barrier": recovering a factor's phase, under a continuous reparametrization of the integers, is equivalent to factoring. That lens gives no shortcut to breaking RSA. Negative knowledge, but rigorous and useful — and I've just generalized it: it holds for any logarithmic-scale lens, not only the silver ratio.

From the theory I built something practical: an open-source, defensive key auditor covering RSA **and ECC** — it detects known weak classes (close primes, shared factors, ROCA-style bias, ECDSA nonce reuse) to help people protect their keys. The ECC side in particular is rarely packaged in accessible tools.

I did all of this alone, unfunded, driven by love of research. My dream is simple: to be able to live from doing research.

If this resonates — if you work in security/cryptography, or know someone who values independent research — I'd love to talk, collaborate, or hear your feedback.

📄 Paper (DOI): https://doi.org/10.5281/zenodo.14553556
💻 Auditor (open-source): https://github.com/FlowAgro/honest-key-audit

#cryptography #infosec #numbertheory #research #opensource #RSA #ECC
