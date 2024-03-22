import sqlite3

def db_connection(func):
    def wrapper(self, *args, **kwargs):
        self.database = sqlite3.connect(self.database_path)
        self.cursor = self.database.cursor()
        try:
            result = func(self, *args, **kwargs)
            self.database.commit()
            return result
        finally:
            self.database.close()
    return wrapper

class Database:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    @db_connection    
    def insert_into_data_script(self, script_point: str, ura: str, state: str, name_update_data: str, variable: str) -> None:
        self.cursor.execute(f"INSERT INTO data_script VALUES ('{script_point}', '{ura}', '{state}', '{name_update_data}', '{variable}')")

    @db_connection
    def select_data_script(self, colunas: str = '*', condition: str = '') -> list:
        result = self.cursor.execute(f"SELECT {colunas} FROM data_script {condition}")
        return result.fetchall()

    @db_connection    
    def update_data_script(self, data: str, condition: str) -> None:
        self.cursor.execute(f"UPDATE data_script SET {data} {condition}")

    @db_connection    
    def delete_data_script(self, condition: str) -> None:
        self.cursor.execute(f"DELETE FROM data_script {condition}")

    @db_connection    
    def insert_into_data_flow(self, id: str, name: str, description: str, type: str, active: int, deleted: int, published_version_id: str, create_name: str, date_published: str) -> None:
        active = 1 if active else 0
        deleted = 1 if deleted else 0
        self.cursor.execute(f"INSERT INTO data_flow VALUES ('{id}', '{name}', '{description}', '{type}', {active}, {deleted}, '{published_version_id}', '{create_name}', '{date_published}')")

    @db_connection
    def select_data_flow(self, colunas: str = '*', condition: str = '') -> list:
        result = self.cursor.execute(f"SELECT {colunas} FROM data_flow {condition}")
        tabela = result.fetchall()
        if len(tabela) == 0:
            return tabela
        if 'active' in colunas or colunas == '*':
            indice_active = colunas.split(', ').index('active') if 'active' in colunas else 4
        if 'deleted' in colunas or colunas == '*':
            indice_deleted = colunas.split(', ').index('deleted') if 'deleted' in colunas else 5
        for indice, linha in enumerate(tabela):
            aux = list(linha)
            if 'active' in colunas or colunas == '*':
                aux[indice_active] = True if aux[indice_active] == 1 else False
            if 'deleted' in colunas or colunas == '*':
                aux[indice_deleted] = True if aux[indice_deleted] == 1 else False
            tabela[indice] = tuple(aux)
        return tabela

    @db_connection    
    def update_data_flow(self, data: str, condition: str) -> None:
        self.cursor.execute(f"UPDATE data_flow SET {data} {condition}")

    @db_connection    
    def delete_data_flow(self, condition: str) -> None:
        self.cursor.execute(f"DELETE FROM data_flow {condition}")

    @db_connection    
    def insert_into_data_action(self, mutant_id: int, name: str, description: str, integrationId: str, category: str, properties_output:str, properties_input:str, request_url:str, request_type:str, request_headers:str, request_body:str, response:str, flow_id: str, flow_deleted: str, ura: str, state: str) -> None:
        self.cursor.execute(f"INSERT INTO data_action VALUES ('{mutant_id}', {name}', {description}', {integrationId}', {category}', {properties_output}', {properties_input}', {request_url}', {request_type}', {request_headers}', {request_body}', {response}', {flow_id}', {flow_deleted}', '{ura}', '{state}')")

    @db_connection
    def select_data_action(self, colunas: str = '*', condition: str = '') -> list:
        result = self.cursor.execute(f"SELECT {colunas} FROM data_action {condition}")
        return result.fetchall()

    @db_connection    
    def update_data_action(self, data: str, condition: str) -> None:
        self.cursor.execute(f"UPDATE data_action SET {data} {condition}")

    @db_connection    
    def delete_data_action(self, condition: str) -> None:
        self.cursor.execute(f"DELETE FROM data_action {condition}")
