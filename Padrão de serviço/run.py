# Importação dos módulos necessários do Flask e outras bibliotecas.
from flask import Flask, jsonify, request, redirect, url_for, session, flash, send_from_directory, render_template
from flask_sqlalchemy import SQLAlchemy  # Importação da extensão SQLAlchemy para operações de banco de dados com Flask.
from werkzeug.security import generate_password_hash, check_password_hash  # Importação de funções de segurança para hashing de senhas.
from werkzeug.utils import secure_filename  # Importação de uma função para garantir que um nome de arquivo é seguro.
import os  # Importação do módulo os para interagir com o sistema operacional.

# Inicialização da instância da aplicação Flask.
app = Flask(__name__)
# Configuração de uma chave secreta para a aplicação, importante para a segurança das sessões.
app.secret_key = '29100619'  # Deve ser substituída por uma chave secreta real em um ambiente de produção.
# Configuração do caminho da pasta para uploads, baseado no diretório atual do arquivo do aplicativo.
app.config['CUSTOM_UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')    
# Configuração da URI do banco de dados para utilizar SQLite, com o arquivo de banco de dados localizado no mesmo diretório do aplicativo.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)  # Inicialização do objeto SQLAlchemy com a aplicação Flask configurada.

# Definição da tabela associativa para um relacionamento muitos-para-muitos entre os modelos User e PDF.
user_pdfs = db.Table('user_pdfs',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),  # Coluna de chave estrangeira para o ID do usuário.
    db.Column('pdf_id', db.Integer, db.ForeignKey('pdf.id'), primary_key=True)  # Coluna de chave estrangeira para o ID do PDF.
)

# Definição da classe do modelo User, que representa os usuários no banco de dados.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Campo ID único para o usuário, chave primária na tabela.
    username = db.Column(db.String(80), unique=True, nullable=False)  # Nome de usuário, deve ser único e não nulo.
    password = db.Column(db.String(120), nullable=False)  # Senha do usuário, armazenada como hash e não nula.
    is_admin = db.Column(db.Boolean, default=False)  # Indicador se o usuário é administrador, com valor padrão falso.
    nome = db.Column(db.String(100))  # Campo para o nome do usuário.
    # Definição do relacionamento muitos-para-muitos com o modelo PDF, utilizando a tabela associativa user_pdfs.
    pdfs = db.relationship('PDF', secondary=user_pdfs, backref=db.backref('users', lazy='dynamic'))

# Definição da classe do modelo PDF, que representa os arquivos PDF no banco de dados.
class PDF(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Campo ID único para o PDF, chave primária na tabela.
    file_path = db.Column(db.String(120), nullable=False)  # Caminho do arquivo PDF no sistema, não pode ser nulo.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Chave estrangeira opcional para o ID do usuário associado.




# Utiliza o contexto da aplicação Flask para operações que dependem do estado da aplicação.
with app.app_context():
    db.create_all()  # Cria todas as tabelas no banco de dados com base nos modelos definidos anteriormente (User e PDF).

# Define uma rota dinâmica que irá atender a requisições de arquivos de qualquer caminho.
@app.route('/uploads/<path:filename>')
def route_file(filename):
    # Tenta verificar se o arquivo solicitado existe na pasta 'templates', que é padrão para arquivos estáticos do Flask.
    try:
        # Tenta renderizar o arquivo como um template. Se ele existir, o Flask irá renderizá-lo e retorná-lo como resposta.
        return render_template(filename)
    except:
        # Caso o arquivo não esteja na pasta 'templates', ou algum erro ocorra ao tentar renderizá-lo, executa o código no bloco except.
        # Monta o caminho completo até a pasta de uploads, configurada anteriormente.
        uploads_path = os.path.join(app.root_path, app.config['CUSTOM_UPLOAD_FOLDER'])
        # Verifica se o arquivo existe no caminho montado (dentro da pasta de uploads).
        if os.path.exists(os.path.join(uploads_path, filename)):
            # Se o arquivo existir na pasta de uploads, retorna o arquivo solicitado diretamente.
            return send_from_directory(uploads_path, filename)
        else:
            # Se o arquivo não for encontrado nem na pasta de templates nem na de uploads, retorna uma mensagem de erro 404 (não encontrado).
            return "File not found.", 404





from datetime import datetime

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    nome = db.Column(db.String(100))  # Adicionado campo para nome
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)


with app.app_context():
    db.create_all()  # Adiciona a criação da tabela de log de login.













# Cria as tabelas no banco de dados
with app.app_context():  # Utiliza o contexto da aplicação para garantir que estamos no contexto correto para operações de banco de dados.
    db.create_all()  # Comando para criar todas as tabelas definidas nos modelos, caso ainda não existam no banco de dados.

# Decorador do Flask que define uma rota para servir arquivos estáticos.
@app.route('/static/<path:filename>')  # O '<path:filename>' é uma variável dinâmica no URL que representa o caminho do arquivo solicitado.
def serve_static(filename):  # Define a função que será chamada quando esta rota for acessada.
    # Retorna o arquivo estático solicitado da pasta 'static'.
    return send_from_directory('static', filename)  # 'static' é o nome padrão da pasta onde o Flask serve arquivos estáticos.

# Decorador do Flask que define a rota '/home'.
@app.route('/home')
def home():  # Função chamada quando a rota '/home' é acessada.
    # Verifica se a chave 'user_id' está presente na sessão do usuário atual.
    if 'user_id' in session:
        # Se o usuário estiver logado, busca a instância do usuário no banco de dados pelo 'user_id' armazenado na sessão.
        user = User.query.get(session['user_id'])
        # Busca todos os PDFs acessíveis pelo usuário, utilizando a relação muitos-para-muitos e o filtro pela ID do usuário.
        accessible_pdfs = PDF.query.join(user_pdfs).filter(user_pdfs.c.user_id == user.id).all()
        # Renderiza o template 'home.html' passando a lista de PDFs acessíveis para o usuário.
        return render_template('home.html', accessible_pdfs=accessible_pdfs)
    # Se 'user_id' não estiver na sessão, o usuário não está logado.
    return redirect(url_for('login'))  # Redireciona para a rota '/login'.





@app.route('/')
def index():
    return redirect(url_for('login'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login bem-sucedido!', 'success')
            
            # Registrar log de login com nome
            log = LoginLog(username=user.username, nome=user.nome, success=True)
            db.session.add(log)
            db.session.commit()

            return redirect(url_for('home'))
        else:
            # Registrar tentativa de login fracassada (não é necessário o nome)
            log = LoginLog(username=username, success=False)
            db.session.add(log)
            db.session.commit()
            flash('Usuário ou senha incorretos', 'error')
    return render_template('login.html')


@app.route('/login_logs')
def login_logs():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    username = request.args.get('username')
    nome = request.args.get('nome')
    success = request.args.get('success')

    query = LoginLog.query

    if start_date:
        query = query.filter(LoginLog.timestamp >= start_date)
    if end_date:
        query = query.filter(LoginLog.timestamp <= end_date)
    if username:
        query = query.filter(LoginLog.username == username)
    if nome:
        query = query.filter(LoginLog.nome == nome)
    if success in ['true', 'false']:
        query = query.filter(LoginLog.success == (success == 'true'))

    logs = query.all()
    return render_template('login_logs.html', logs=logs)







import pandas as pd
from io import BytesIO
from flask import send_file, request
from datetime import datetime
@app.route('/download_excel')
def download_excel():
    # Obtenha os mesmos parâmetros de filtro
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    username = request.args.get('username')
    nome = request.args.get('nome')
    success = request.args.get('success')

    # Filtre os logs de login do banco de dados com base nos parâmetros
    query = LoginLog.query
    if start_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(LoginLog.timestamp >= start_date_obj)
        except ValueError:
            pass  # Ignora o filtro se a data inicial não for válida
    if end_date:
        try:
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(LoginLog.timestamp <= end_date_obj)
        except ValueError:
            pass  # Ignora o filtro se a data final não for válida
    if username:
        query = query.filter(LoginLog.username.contains(username))
    if nome:
        query = query.filter(LoginLog.nome.contains(nome))
    if success in ['true', 'false']:
        query = query.filter(LoginLog.success == (success == 'true'))

    logs = query.all()

    # Converter os logs filtrados para um DataFrame do Pandas
    data = {
        "Data/Hora": [log.timestamp for log in logs],
        "Cartão": [log.username for log in logs],
        "Matricula": [log.nome for log in logs],
        "Sucesso": ['Sim' if log.success else 'Não' for log in logs]
    }
    df = pd.DataFrame(data)

    # Use BytesIO para manipulação em memória do arquivo Excel
  
    # Use BytesIO para manipulação em memória do arquivo Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Logs')

    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='logs.xlsx'  # Correção aqui
    )











@app.route('/update_user_access', methods=['POST'])
def update_user_access():
    data = request.get_json()
    user_id = data['user_id']
    pdf_ids = data['pdf_ids']

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    # Atualize os acessos do usuário
    user.pdfs = [PDF.query.get(pdf_id) for pdf_id in pdf_ids]
    db.session.commit()

    return jsonify({'message': 'Acesso aos aos pardões de serviço tualizado com sucesso'})











@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_admin:
            users = User.query.all()
            return render_template('admin.html', users=users)
    return redirect(url_for('home'))





@app.route('/manage_pdfs/<user_id>', methods=['GET', 'POST'])
def manage_pdfs(user_id):
    user = User.query.get(user_id)
    if user:
        if request.method == 'POST':
            pass
        return render_template('manage_pdfs.html', user=user)
    else:
        flash('Usuário não encontrado', 'error')
        return redirect(url_for('admin'))

@app.route('/remove_pdf', methods=['POST'])
def remove_pdf():
    if 'user_id' in request.form:
        user_id = request.form['user_id']
        return redirect(url_for('admin'))
    else:
        flash('Erro ao remover PDF', 'error')
        return redirect(url_for('admin'))

@app.route('/create_user', methods=['POST'])
def create_user():
    nome = request.form.get('nome')
    new_username = request.form.get('new_username')
    new_password = request.form.get('new_password')
    # ... lógica de verificação e criação do usuário ...
    user = User(nome=nome, username=new_username, password=generate_password_hash(new_password))
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('admin'))










@app.route('/get_user_pdfs/<int:user_id>')
def get_user_pdfs(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    # Obtenha todos os PDFs e se o usuário tem acesso a eles
    all_pdfs = PDF.query.all()
    user_pdf_ids = [pdf.id for pdf in user.pdfs]  # IDs dos PDFs aos quais o usuário tem acesso

    pdfs_data = [{
        'id': pdf.id,
        'file_path': pdf.file_path,
        'access': pdf.id in user_pdf_ids  # Booleano se o usuário tem acesso
    } for pdf in all_pdfs]

    return jsonify(pdfs_data)














@app.route('/update_pdf_access', methods=['POST'])
def update_pdf_access():
    user_id = request.json.get('user_id')
    pdf_ids = request.json.get('pdf_ids')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    # Atualiza a lista de PDFs aos quais o usuário tem acesso
    user.pdfs = PDF.query.filter(PDF.id.in_(pdf_ids)).all()
    db.session.commit()

    return jsonify({'message': 'Acesso aos PDFs atualizado com sucesso'})

    







app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


@app.route('/uploads/<filename>')
def uploaded_files(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)















@app.route('/add_pdf_access', methods=['POST'])
def add_pdf_access():
    data = request.get_json()
    # Aqui você adicionaria a lógica para adicionar o acesso ao PDF no banco de dados
    return jsonify({'message': 'Acesso ao PDF adicionado'})

@app.route('/remove_pdf_access', methods=['POST'])
def remove_pdf_access():
    data = request.get_json()
    # Aqui você adicionaria a lógica para remover o acesso ao PDF no banco de dados
    return jsonify({'message': 'Acesso ao PDF removido'})















@app.route('/list-html')
def list_html_files():
    # Lista todos os arquivos no diretório UPLOAD_FOLDER que terminam com '.html'
    html_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith('.html')]
    return render_template('list_html.html', html_files=html_files)



@app.route('/edit_pdf/<int:pdf_id>', methods=['POST'])
def edit_pdf(pdf_id):
    pdf = PDF.query.get_or_404(pdf_id)
    data = request.get_json()

    # Atualize os dados do pdf com a nova informação
    pdf.file_path = data['file_path']
    # Salve as alterações no banco de dados
    db.session.commit()

    return jsonify({'message': 'PDF updated successfully'}), 200








@app.route('/get_pdf')
def get_pdf():
    pdf = PDF.query.all()
    pdf_list = []
    for pdf in pdfs:
        # Obtenha todos os usuários que têm acesso a este PDF.
        pdf_list.append({
            'id': pdf.id,
            'file_path': pdf.file_path,  # Isso deve ser apenas o nome do arquivo, conforme salvo acima
        })
    return jsonify(pdf_list)










@app.route('/create_page', methods=['GET', 'POST'])
def create_page():
    if request.method == 'POST':
        title = request.form['pageTitle']
        text = request.form['pageText']

        folder_name = secure_filename(title)
        page_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)

        if not os.path.exists(page_folder_path):
            os.makedirs(page_folder_path)

        pdf_file = request.files.get('pageFile')
        rel_pdf_path = None

        if pdf_file and pdf_file.filename.endswith('.pdf'):
            pdf_filename = secure_filename(pdf_file.filename)
            pdf_filepath = os.path.join(page_folder_path, pdf_filename)
            pdf_file.save(pdf_filepath)
            rel_pdf_path = os.path.join(folder_name, title + '.pdf')

        html_filename = secure_filename(title) + '.html'
        html_filepath = os.path.join(page_folder_path, html_filename)

        html_content = render_template('page_template.html', title=title, text=text, pdf_filename=pdf_filename if pdf_file else None)

        with open(html_filepath, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)

        # Criando a instância de PDF com o caminho do arquivo HTML
        new_pdf = PDF(file_path=os.path.join(folder_name, html_filename), user_id=1)  # Substitua 1 pelo ID do usuário apropriado
        db.session.add(new_pdf)

        db.session.commit()

        flash('Página HTML e PDF (se enviado) criados com sucesso!')
        return redirect(url_for('admin'))

    return render_template('create_page.html')












import os

@app.route('/update_pdf')
def update_pdfs():
    # Certifique-se que a pasta UPLOAD_FOLDER existe e tem os arquivos HTML
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        return "Diretório de upload não encontrado.", 404

    # Obtenha todos os arquivos HTML
    html_files = [f for f in os.listdir(upload_folder) if f.endswith('.html')]

    # Para cada arquivo HTML, adicione-o ao banco de dados se ainda não estiver registrado
    for html_file in html_files:
        file_path = os.path.join(upload_folder, html_file)
        # Verifique se o arquivo já está registrado no banco de dados
        pdf_entry = PDF.query.filter_by(file_path=file_path).first()
        if not pdf_entry:
            # Se não estiver registrado, crie um novo registro e adicione-o ao banco de dados
            new_pdf = PDF(file_path=file_path)
            db.session.add(new_pdf)
    
    # Commit as mudanças no banco de dados
    db.session.commit()

    return "PDFs atualizados com sucesso!", 200






# ... (importações e configurações do Flask) ...

@app.route('/change_user_password', methods=['POST'])
def change_user_password():
    data = request.get_json()
    user_id = data['user_id']
    new_password = data['new_password']

    user = User.query.get(user_id)
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Senha alterada com sucesso.'})
    else:
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404

# ... (restante do código do Flask) ...



@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Usuário excluído com sucesso', 'success')
    else:
        flash('Usuário não encontrado', 'error')

    return redirect(url_for('admin'))
















if __name__ == '__main__':

    app.run(debug=True, port=9001, host='0.0.0.0')  # Configuração alterada para usar a porta 9090 e o host '0.0.0.0'
