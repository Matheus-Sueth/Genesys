import threading
import queue

class Thread(threading.Thread):
    def __init__(self, funcao, name: str, args: tuple, daemon: bool = True) -> None:
        super().__init__(target=self.funcao_thread, name=name, daemon=daemon)
        self.funcao = funcao
        self.args = args
        self.resultados = queue.Queue()

    def funcao_thread(self) -> None:
        resultado = self.funcao(*self.args)
        self.resultados.put(resultado)

    def get_resultado(self) -> object:
        return self.resultados.get()
