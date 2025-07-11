# Define a variável de usuário para facilitar a portabilidade
USER="odirlei"

# 1. Atualizar o sistema e instalar ferramentas essenciais
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv curl wget git dnsutils

# 2. Navegar para o diretório base do usuário e clonar o repositório
cd /home/$USER/

# Remove o diretório se já existir para garantir uma instalação limpa
# CUIDADO: Este comando apaga o diretório 'monitoramento' se ele existir.
# Se você tiver dados importantes nele, faça um backup antes.
sudo rm -rf monitoramento

# Clona o repositório Git. Isso criará o diretório 'monitoramento'
git clone https://github.com/odirleisias/testeurl.git monitoramento

# 3. Navegar para o diretório da aplicação clonada
cd monitoramento

# 4. Criar o arquivo requirements.txt (se ele não estiver no seu repositório)
# Se você já adicionou requirements.txt ao seu repositório, pode pular esta etapa.
# Caso contrário, adicione-o ao seu repositório para futuras instalações mais limpas.
echo "requests" > requirements.txt
echo "flask" >> requirements.txt
echo "tldextract" >> requirements.txt
echo "dnspython" >> requirements.txt

# 5. Criar e ativar o ambiente virtual Python
python3 -m venv venv
source venv/bin/activate

# 6. Instalar as dependências Python
pip install -r requirements.txt

# 7. Garantir permissão na porta 80 e executar a aplicação
# Configura o firewall para permitir tráfego na porta 80 (se ainda não estiver aberto)
# sudo ufw allow 80/tcp
# sudo ufw enable # Ativa o firewall se não estiver ativo. Confirme a operação.

# Executa a aplicação.
# Mantenha este comando rodando em um terminal, ou use screen/tmux para desanexar
sudo venv/bin/python3 monitora.py
