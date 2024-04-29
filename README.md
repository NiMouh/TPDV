# Trabalho prático 1 de Ambientes de Execução Seguros

## Autores
- João Almeida ()
- Simão Andrade (118345)

## Objetivos

Implementar um cofre digital à **prova de adulteração de arquivos** (TPDV), utilizando **Intel SGX enclaves**. O cofre pode ser destruído, mas nunca vai ser possível mudar o conteúdo dos arquivos sem que o cofre perceba. O foco desta implementação é a **integridade** dos arquivos, **não a confidencialidade**.

O programa deve ser capaz de:
- [x] Criar um ficheiro TPDV.
- [ ] Adicionar um arquivo ao TPDV.
- [ ] Listar os arquivos no TPDV.
- [ ] Extrair um arquivo (ou todos) do TPDV.
- [ ] Calcular o hash de um arquivo no TPDV.
- [ ] Alterar a password do TPDV.
- [ ] Clonar o TPDV para outro SGX enclave.

## Implementação

Os dados do TPDV são selados (*sealed*) e armazenados num ficheiro. Toda a informação é armazenada num `unsigned int array`.

O cabeçalho do ficheiro é composto por:

<p align="center">
  <img src="img/tpdv.png" alt="Cabeçalho do ficheiro TPDV" width="1200"/>
</p>
<p align="center">
  <i>Fig. 1 - Cabeçalho do TPDV</i>
</p>

Cada ficheiro adicionado ao TPDV é composto por:

<p align="center">
  <img src="img/asset.png" alt="Cabeçalho do ficheiro TPDV" width="1200"/>
</p>

<p align="center">
  <i>Fig. 2 - Estrutura de um ficheiro no TPDV</i>
</p>

### Funções

O programa é dividido em **dois tipos** de funções:
- Funções "seguras": são executadas dentro do enclave e têm acesso a memória selada.
  - `unsealed`
  - `sealed`
  - `get_sealed_size`
- Funções "não seguras": são executadas fora do enclave e têm acesso a memória não selada. 
  - `create_tpdv`
  - `add_asset`

#### `create_tpdv`

Esta função é responsável por criar um ficheiro TPDV. O ficheiro é criado com o cabeçalho e o array de ficheiros vazio.

A função tem o seguinte header:
```c
int create_tpdv(uint8_t *filename, size_t filename_size, uint8_t *password, size_t password_size, uint8_t *creator, size_t creator_size);
```

Devolve `0` em caso de sucesso e `-1` ou `1` em caso de erro.


### Fluxo de execução da aplicação

## Compilação

Para compilar o programa, basta executar os seguintes comandos:

```bash
$ make
$ ./app
```

## Conclusão

