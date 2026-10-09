# Trilha de Vendas — Educação em Foco

Plataforma de treinamento em vídeo (módulos, aulas, progresso, anotações, comentários e painel do administrador).
Mesmo esquema do Espelho de Ponto: GitHub + Netlify, dados salvos na nuvem (Netlify Blobs).

## Publicar (site NOVO, separado do Espelho de Ponto)
1. GitHub: crie um repositório novo (ex.: `trilha-vendas`) e envie estas pastas/arquivos mantendo a estrutura:
   `public/index.html`, `netlify/functions/api.mjs`, `netlify.toml`, `package.json`, `package-lock.json`, `.gitignore`.
2. Netlify: Add new site → Import from GitHub → escolha o repositório (sem build command; Publish directory `public`).
3. Site configuration → Environment variables, crie:
   - `SESSION_SECRET` = texto aleatório com 32+ caracteres
   - `AUTH_USERS` = administrador fixo (JSON). Gere o valor com `node gerar-senha.mjs "diogo machado" "SuaSenha"`
     (ou use o mesmo valor do Espelho de Ponto para manter o mesmo login).
4. Deploys → Trigger deploy. Abra o endereço, entre como administrador.

## Primeiros passos
- **Gerenciar módulos**: crie os módulos (ou "Começar com modelo") e cadastre cada aula com o link do YouTube (vídeo **não listado**) e a duração.
- **Acessos**: crie o login de cada vendedora (nome, usuário, senha inicial). Ela pode trocar a senha em "Senha".
- **Acompanhamento**: progresso por vendedora e por módulo, e último acesso.

## Como funciona
- O vídeo toca pelo player do YouTube (modo privacidade). O site salva a posição a cada poucos segundos e retoma de onde parou; a aula conclui sozinha em 90%.
- Anotações são só da pessoa; comentários são visíveis para a equipe (cada um apaga o seu; admin apaga qualquer um).
- Se o YouTube não carregar (rede da empresa bloqueando), aparece um link para abrir no YouTube e o botão "Marcar como concluída".
- Vídeo "não listado" não aparece em busca, mas quem tiver o link consegue abrir; o login protege o *site*, não o link do YouTube.
