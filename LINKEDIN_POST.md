# Post do LinkedIn — rascunhos

## Versão em português (principal)

Tudo começou com uma planilha que preenchi à mão — quase 500 linhas relacionando cada número primo a um padrão que eu sentia existir. Não tenho instituição, bolsa, nem recurso — só a convicção de que havia ali uma estrutura real.

Persegui essa intuição com uma regra inegociável: honestidade absoluta. Verificar tudo computacionalmente. Distinguir o que eu "descobri" do que a matemática já conhecia. E aceitar os resultados negativos como conhecimento de verdade.

O resultado que sobreviveu ao escrutínio é um teorema no-go — a "Barreira": recuperar a fase de um fator, sob uma reparametrização contínua dos inteiros, é equivalente a fatorar. Ou seja, essa lente não dá atalho nenhum para quebrar RSA. É conhecimento negativo, mas rigoroso e útil — e acabei de generalizá-lo: vale para qualquer lente de escala logarítmica, não só para a razão de prata.

O mesmo método que usei nos primos — *testar a distribuição que um gerador realmente produz* — virou uma ferramenta open-source para o problema criptográfico do momento: **a migração pós-quântica**. O NIST padronizou o pós-quântico em 2024 (ML-KEM, ML-DSA), e a segurança desses esquemas depende da **qualidade de um amostrador**. Um amostrador viciado enfraquece a chave em silêncio — e os testes clássicos de aleatoriedade não pegam. Minha ferramenta **certifica** esse amostrador por três lentes independentes (distribuição, correlação serial, periodicidade), e de quebra audita chaves RSA/ECC clássicas (ROCA, batch-GCD, Fermat, reuso de nonce ECDSA) na mesma caixa.

Fiz tudo isso sozinho, sem apoio, movido por amor à pesquisa. Meu sonho é simples: poder viver de pesquisar — o mundo é fascinante demais para não investigá-lo.

Se você atua com segurança/criptografia, está pensando em **cripto-agilidade / prontidão pós-quântica**, ou conhece alguém que valorize pesquisa independente: eu adoraria conversar, colaborar ou ouvir seu feedback.

📄 Paper (DOI): https://doi.org/10.5281/zenodo.14553556
💻 Ferramenta (open-source): https://github.com/FlowAgro/honest-key-audit

#criptografia #segurançadainformação #pósquântico #PQC #cibersegurança #opensource #pesquisa

---

## English version (for reach)

It started with a spreadsheet I filled out by hand — ~500 rows linking each prime to a pattern I sensed was there. No institution, no grant, no funding — just the conviction that a real structure was hiding in it.

I chased that intuition with one non-negotiable rule: absolute honesty. Verify everything computationally. Separate what I "discovered" from what mathematics already knew. Treat negative results as real knowledge.

What survived the scrutiny is a no-go theorem — "the Barrier": recovering a factor's phase, under a continuous reparametrization of the integers, is equivalent to factoring. That lens gives no shortcut to breaking RSA. Negative knowledge, but rigorous and useful — and I've just generalized it: it holds for any logarithmic-scale lens, not only the silver ratio.

The same method I used on the primes — *test the distribution a generator actually emits* — became an open-source tool for the crypto problem of the moment: **the post-quantum migration.** NIST standardized PQC in 2024 (ML-KEM, ML-DSA), and the security of these schemes hinges on **the quality of a sampler.** A biased sampler silently weakens the key — and classical randomness tests don't catch it. My tool **certifies** that sampler through three independent lenses (distribution, serial correlation, periodicity), and audits classical RSA/ECC keys (ROCA, batch-GCD, Fermat, ECDSA nonce reuse) in the same box.

I did all of this alone, unfunded, driven by love of research. My dream is simple: to be able to live from doing research.

If you work in security/cryptography, are thinking about **crypto-agility / post-quantum readiness**, or know someone who values independent research — I'd love to talk, collaborate, or hear your feedback.

📄 Paper (DOI): https://doi.org/10.5281/zenodo.14553556
💻 Tool (open-source): https://github.com/FlowAgro/honest-key-audit

#cryptography #infosec #postquantum #PQC #cybersecurity #opensource #research
