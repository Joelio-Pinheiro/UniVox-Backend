# UniVox - Setup do Ambiente de Desenvolvimento

Este guia explica como configurar o ambiente local para rodar o UniVox em sua máquina.

---

## ✅ Pré-requisitos

* [Python 3.13+](https://www.python.org/)
* [Docker e Docker Compose](https://www.docker.com/)
* [Git](https://git-scm.com/)
* [WSL](Instalação Abaixo)

---

## 🚀 Passo a passo para rodar o projeto

### 1. Clone o repositório

```bash
git clone https://github.com/Joelio-Pinheiro/UniVox-Backend.git
cd UniVox-Backend
```

### 2. Crie o ambiente virtual (venv)

```bash
python -m venv venv
```

### 3. Ative o ambiente virtual

* **Linux:**

  ```bash
  source venv/bin/activate
  ```

* **Windows (CMD):**

  ```cmd
  venv\Scripts\activate
  ```

* **Windows (PowerShell):**

  ```powershell
  .\venv\Scripts\Activate
  ```

### 4. Instale as dependências

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuração de variáveis de ambiente

Copie o arquivo de exemplo:

```bash
cp .env.example .env
```


---

## 🐳 Subindo o banco de dados com Docker

```bash
docker-compose up -d
```

> ⚠️ **Importante:** o app do docker e o container do banco precisa estar rodando sempre que for usar o projeto.

---

## 🛠️ Migrações do banco de dados

```bash
python manage.py migrate
```

---

## 👤 Crie um superusuário para acessar o admin

```bash
python manage.py createsuperuser
```

---

## ▶️ Rodando o servidor de desenvolvimento

```bash
python manage.py runserver
```

Acesse em: [http://localhost:8000](http://localhost:8000)

---

## 🧪 Comandos úteis


* Entrar no banco de dados via Docker:

  ```bash
  docker exec -it univox_postgres bash
  psql -U univox_user -d univox_db
  ```

* Listar tabelas no PostgreSQL:

  ```sql
  \d
  ```

---


## 📌 Notas

* O Django usa o banco PostgreSQL que roda no container Docker.
* Não é necessário instalar PostgreSQL localmente.

## Pré-requisito: Instalar WSL no Windows

Para rodar o projeto usando Docker no Windows, é necessário ter o **WSL (Windows Subsystem for Linux)** instalado e configurado. Siga os passos abaixo para instalar o WSL com a distribuição Ubuntu 24.04:

1. **Abra o PowerShell como Administrador**  
   - Clique no menu Iniciar, digite `PowerShell`, clique com o botão direito em **Windows PowerShell** e selecione **Executar como administrador**.

2. **Liste as distribuições Linux disponíveis:**
   ```bash
   wsl -l -o
3. **Instale a distribuição Ubuntu 24.04 (ou a mais recente disponível):**
    ```bash
    wsl --install -d Ubuntu-24.04
4. **Reinicie o computador**

5. **Após reiniciar, abra o Ubuntu (WSL):**

   * No menu Iniciar, procure por **Ubuntu 24.04** e abra o terminal.

6. **Configure seu usuário e senha no Ubuntu:**

   * Siga as instruções para criar um usuário e senha que serão usados dentro do WSL.
