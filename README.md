# Automate Army Checks

Conecte um projeto ao [Checks](https://checks.apps.automatearmy.com/) adicionando
um workflow. Trivy verifica dependências, configurações e segredos; o SBOM é
enviado ao Dependency-Track com autenticação temporária do GitHub OIDC.

## Conectar um projeto

Nos repositórios da organização `automatearmy`, crie `.github/workflows/checks.yml`:

```yaml
name: Checks
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
  id-token: write
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1
```

Não precisa cadastrar UUID, criar secret nem instalar um agente no servidor.
Na primeira execução na branch padrão, o projeto `OWNER/REPO` é criado
automaticamente. O inventário dessa branch é atualizado a cada execução;
o GitHub registra o commit e os resultados no resumo da execução.

Também pode gerar o arquivo após clonar este repositório:

```sh
python3 /caminho/checks-action/scripts/connect.py --project-dir /caminho/do/projeto
```

O instalador preserva workflows existentes e recusa sobrescrever `checks.yml`.
Para fixar uma versão revisada, acrescente `--ref SHA_COMPLETO_DA_RELEASE`.
Não usa `curl | bash` nem precisa de credencial administrativa no projeto.

## Comportamento

- Push na branch padrão, execução manual nessa branch e agendamento nessa branch:
  varredura, autenticação OIDC, criação/atualização do projeto e espera pela análise.
- Pull requests e outras branches: varredura local e bloqueio por severidade;
  não solicitam token OIDC do Checks nem atualizam o inventário da branch padrão.
- O bloqueio padrão inclui `HIGH` e `CRITICAL` em vulnerabilidades, configurações
  inválidas e segredos. O envio do SBOM ocorre antes do bloqueio, preservando os
  achados no painel mesmo quando o job termina com falha.
- Só o SBOM é enviado. Código-fonte e relatório bruto de segredos permanecem no
  runner, em diretório privado; não são publicados como artifacts nem no log.
- O cliente falha em erro de rede, falha de processamento ou timeout de dez minutos.
  Um envio concluído não garante que todas as fontes de vulnerabilidades estejam atualizadas.
- Runners Linux com Docker e Python 3 são necessários. O workflow usa `ubuntu-latest`.
  Imagens são consultadas no registry, sem montagem do socket Docker no scanner.

Para escanear uma imagem publicada em vez do código:

```yaml
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1
    with:
      mode: image
      target: ghcr.io/automatearmy/meu-projeto:versao
    # Para registry privado, passe apenas credenciais de leitura:
    # secrets:
    #   registry-username: ${{ secrets.REGISTRY_USERNAME }}
    #   registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

Inputs: `mode` (`fs` ou `image`), `target` (padrão `.`), `fail-on` (padrão
`HIGH,CRITICAL`; `NONE` é uma opção explícita para observar sem bloquear).
O envio ao Checks mantém a mesma regra da branch padrão.

## Configuração única da organização

Esta etapa é para administradores do Checks. Os projetos conectados não repetem
o processo e não recebem a credencial administrativa.

1. Permitir o uso desta Action privada pelos repositórios da organização em
   Settings → Actions → General → Access, ou pela API do GitHub.
2. Disponibilizar `CHECKS_ADMIN_KEY` ou `CHECKS_ADMIN_TOKEN` no ambiente do operador,
   com `ACCESS_MANAGEMENT`. Não colocar o valor na linha de comando ou no Git.
3. Revisar a release e cadastrar seu SHA completo:

```sh
python3 scripts/configure.py --trusted-workflow-sha SHA_COMPLETO
python3 scripts/configure.py --trusted-workflow-sha SHA_COMPLETO --apply
```

A configuração registra o issuer oficial do GitHub, audience exclusiva do Checks,
sessões de 15 minutos e uma conta de serviço com `BOM_UPLOAD`,
`PROJECT_CREATION_UPLOAD` e `VIEW_PORTFOLIO`. Não cria chave para essa conta.
As regras validam o ID numérico da organização, o caminho do workflow e o SHA
exato da release aprovada; reconhecem os formatos antigo e imutável de `sub`.
Um workflow copiado ou alterado em outro repositório não recebe essa identidade.

Ao atualizar, repita `--trusted-workflow-sha` para cada release que deve continuar
autorizada. O comando é idempotente e recusa providers/contas existentes com
configuração incompatível. Após a configuração, descarte a credencial temporária
do operador. Pessoas continuam usando Google SSO no painel.

A identidade central atende os projetos da organização; não é uma identidade
isolada por projeto. O workflow aprovado fixa o nome do projeto ao repositório
chamador. Requisitos de isolamento por projeto demandam contas e ACLs próprias.

## Desenvolvimento

```sh
python3 -m unittest discover -s tests -v
```

O workflow `Integration smoke test` executa a integração real por OIDC, sob demanda.
O scan local pode ser executado sem autenticação:

```sh
python3 scripts/checks.py --target /caminho/do/projeto --upload false
```

Base da implementação: [workload identity no Dependency-Track 5.2](https://dependencytrack.github.io/docs/next/guides/administration/configuring-workload-identity-federation/),
[OIDC no GitHub Actions](https://docs.github.com/en/actions/reference/security/oidc),
[Trivy SBOM](https://trivy.dev/docs/latest/guide/supply-chain/sbom/).
