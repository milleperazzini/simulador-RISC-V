import tkinter as tk
from tkinter import ttk

instrucoes = []        # Lista com todas as instruções carregadas
pipeline = [None]*5    # Pipeline com 5 estágios: IF, ID, EX, MEM, WB
pc = 0                 # Program Counter: próxima instrução a entrar no pipeline
R = [0] * 32           # Registradores x0-x31
M = bytearray(1000)    # Memória de 1000 bytes
ciclo = 0              # Contador de ciclos

def carregar_asm(caminho):
    with open(caminho, 'r', encoding='utf-8') as arquivo:
        linhas = arquivo.readlines()

    data = {}
    labels = {}
    ehtexto = False
    ehdata = False
    cont = 0

    for linha in linhas:
        linha = linha.strip()
        if linha == "" or linha.startswith("#"):
            continue

        if linha == ".data":
            ehdata = True
            ehtexto = False
            continue

        elif linha == ".text":
            ehtexto = True
            ehdata = False
            continue

        if ehdata:
            if ':' in linha:
                rotulo, resto = linha.split(":", 1)
                rotulo = rotulo.strip()
                resto = resto.strip()
                if resto.startswith(".asciz"):
                    valor = resto[len(".asciz"):].strip().strip('"')
                    data[rotulo] = valor
        elif ehtexto:
            linha = linha.split("#")[0].strip()  # Remove comentário na linha

            if linha.endswith(":"):  # Caso linha seja só o rótulo
                rotulo = linha[:-1].strip()
                labels[rotulo] = cont  # Salva a posição da próxima instrução
            elif ':' in linha:  # Caso linha tenha rótulo + instrução (ex: "loop: beq ...")
                rotulo, instr = linha.split(":", 1)
                rotulo = rotulo.strip()
                instr = instr.strip()
                labels[rotulo] = cont
                if instr:
                    instrucoes.append(instr)
                    cont += 1
            elif linha:
                instrucoes.append(linha)
                cont += 1
    print(labels);
    return instrucoes, data, labels

def carregar_bin(caminho):
    with open(caminho, 'rb') as arquivo:
        dados = arquivo.read()

    lista = []
    for i in range(0, len(dados), 4):
        pedaco = dados[i:i+4]
        if len(pedaco) < 4:
            continue
        numero = int.from_bytes(pedaco, 'little')
        if numero == 0:
            continue
        binario = f"{numero:032b}"
        lista.append(binario)
    return lista

def reg_to_num(reg):
    # Registradores comuns em RISC-V e seus números
    regs = {
        'x0': 0,  'zero': 0,
        'x1': 1,  'ra': 1,
        'x2': 2,  'sp': 2,
        'x3': 3,  'gp': 3,
        'x4': 4,  'tp': 4,
        'x5': 5,  't0': 5,
        'x6': 6,  't1': 6,
        'x7': 7,  't2': 7,
        'x8': 8,  's0': 8,  'fp': 8,
        'x9': 9,  's1': 9,
        'x10': 10, 'a0': 10,
        'x11': 11, 'a1': 11,
        'x12': 12, 'a2': 12,
        'x13': 13, 'a3': 13,
        'x14': 14, 'a4': 14,
        'x15': 15, 'a5': 15,
        'x16': 16, 'a6': 16,
        'x17': 17, 'a7': 17,
        'x18': 18, 's2': 18,
        'x19': 19, 's3': 19,
        'x20': 20, 's4': 20,
        'x21': 21, 's5': 21,
        'x22': 22, 's6': 22,
        'x23': 23, 's7': 23,
        'x24': 24, 's8': 24,
        'x25': 25, 's9': 25,
        'x26': 26, 's10': 26,
        'x27': 27, 's11': 27,
        'x28': 28, 't3': 28,
        'x29': 29, 't4': 29,
        'x30': 30, 't5': 30,
        'x31': 31, 't6': 31
    }
    reg = reg.lower()
    if reg in regs:
        return regs[reg]
    else:
        raise ValueError(f"Registrador desconhecido: {reg}")

def decodificar(instr):
    if not instr:
        return {"tipo": "NOP", "op": "nop"}

    tokens = instr.replace(",", "").replace("(", " ").replace(")", "").split()
    if not tokens:
        return {"tipo": "NOP", "op": "nop"}

    op = tokens[0]

    if op in ["beq", "bne", "blt", "bge", "bltu", "bgeu", "bgt"]:
        # Usar reg_to_num para rs1 e rs2
        rs1 = reg_to_num(tokens[1])
        rs2 = reg_to_num(tokens[2])
        imm = tokens[3]
        try:
            # Tenta converter o immediate direto
            imm = int(imm)
            return {"tipo": "B", "op": op, "rs1": rs1, "rs2": rs2, "imm": imm}
        except ValueError:
            # Caso não seja um número, assume que é um label
            return {"tipo": "B", "op": op, "rs1": rs1, "rs2": rs2, "label": imm}
    if op in ["add", "sub", "mul", "div", "rem", "xor", "and", "or", "sll", "srl"]:
        # Usar reg_to_num para rd, rs1 e rs2
        return {"tipo": "R", "op": op, "rd": reg_to_num(tokens[1]), "rs1": reg_to_num(tokens[2]), "rs2": reg_to_num(tokens[3])}
    elif op in ["addi", "jalr"]:
        # Usar reg_to_num para rd e rs1
        return {"tipo": "I", "op": op, "rd": reg_to_num(tokens[1]), "rs1": reg_to_num(tokens[2]), "imm": int(tokens[3])}
    elif op == "lw":
        # Usar reg_to_num para rd e rs1
        return {"tipo": "I", "op": op, "rd": reg_to_num(tokens[1]), "imm": int(tokens[2]), "rs1": reg_to_num(tokens[3])}
    elif op == "sw":
        # Usar reg_to_num para rs2 e rs1
        return {"tipo": "S", "op": op, "rs2": reg_to_num(tokens[1]), "imm": int(tokens[2]), "rs1": reg_to_num(tokens[3])}
    elif op == "li":
        return {"tipo": "I", "op": "addi", "rd": reg_to_num(tokens[1]), "rs1": 0, "imm": int(tokens[2])}
    elif op == "mv":
        return {"tipo": "I", "op": "addi", "rd": reg_to_num(tokens[1]), "rs1": reg_to_num(tokens[2]), "imm": 0}
    elif op == "nop":
        return {"tipo": "I", "op": "addi", "rd": 0, "rs1": 0, "imm": 0}
    elif op == "ret":
        return {"tipo": "I", "op": "jalr", "rd": 0, "rs1": 1, "imm": 0}
    elif op == "la":
        return {"tipo": "LA", "op": "la", "rd": reg_to_num(tokens[1]), "label": tokens[2]}
    elif op == "ecall":
        return {"tipo": "SYS", "op": "ecall"}
    elif op == "jal":
        return {"tipo": "J", "op": "jal", "rd": reg_to_num(tokens[1]), "label": tokens[2]}
    elif op == "j":
        return {"tipo": "J", "op": "jal", "rd": 0, "label": tokens[1]}
    else:
        return {"tipo": "NOP", "op": "nop"}

def executar_instrucao(instr):
    if not instr:
        return

    info = decodificar(instr)
    op = info["op"]

    if info["tipo"] == "R":
        rd, rs1, rs2 = info["rd"], info["rs1"], info["rs2"]
        if op == "add":
            R[rd] = R[rs1] + R[rs2]
        elif op == "sub":
            R[rd] = R[rs1] - R[rs2]
        elif op == "mul":
            R[rd] = R[rs1] * R[rs2]
        elif op == "div":
            R[rd] = R[rs1] // R[rs2] if R[rs2] != 0 else 0
        elif op == "rem":
            R[rd] = R[rs1] % R[rs2] if R[rs2] != 0 else 0
        elif op == "xor":
            R[rd] = R[rs1] ^ R[rs2]
        elif op == "and":
            R[rd] = R[rs1] & R[rs2]
        elif op == "or":
            R[rd] = R[rs1] | R[rs2]
        elif op == "sll":
            R[rd] = R[rs1] << R[rs2]
        elif op == "srl":
            R[rd] = R[rs1] >> R[rs2]

    elif info["tipo"] == "I":
        rd, rs1, imm = info["rd"], info["rs1"], info["imm"]
        if op == "addi":
            R[rd] = R[rs1] + imm
        elif op == "lw":
            addr = R[rs1] + imm
            R[rd] = int.from_bytes(M[addr:addr + 4], "little")
        elif op == "jalr":
            R[rd] = pc

    elif info["tipo"] == "S":
        addr = R[info["rs1"]] + info["imm"]
        val = R[info["rs2"]]
        M[addr:addr + 4] = val.to_bytes(4, "little")

    elif op == "la":
        label = info["label"]
        R[info["rd"]] = data.get(label, 0)

    if op == "ecall":
        syscall = R[17]  # a7

        if syscall == 1:
            print(R[10])

        elif syscall == 4:
            print(R[10], end='')
            R[10] = 0

        elif syscall == 5:
            R[10] = int(input())

    R[0] = 0  # zero sempre 0

def atualizar_pipeline_visual():
    IF.delete(0, tk.END)
    ID.delete(0, tk.END)
    EX.delete(0, tk.END)
    MEM.delete(0, tk.END)
    WB.delete(0, tk.END)

    if pipeline[0] is not None:
        IF.insert(tk.END, pipeline[0])
    if pipeline[1] is not None:
        ID.insert(tk.END, pipeline[1])
    if pipeline[2] is not None:
        EX.insert(tk.END, pipeline[2])
    if pipeline[3] is not None:
        MEM.insert(tk.END, pipeline[3])
    if pipeline[4] is not None:
        WB.insert(tk.END, pipeline[4])

def atualizar_registradores_visual():
    registers.delete(0, tk.END)
    for i in range(32):
        registers.insert(tk.END, f"x{i:02d}: {R[i]}")

def atualizar_memoria_visual():
    memory.delete(0, tk.END)
    for i in range(0, len(M), 4):
        word_bytes = M[i:i+4]
        if len(word_bytes) == 4:
            word_value = int.from_bytes(word_bytes, "little")
            memory.insert(tk.END, f"0x{i:03X}: 0x{word_value:08X}")

def escrever_saida():
    with open("saida.out", "a", encoding="utf-8") as f:
        f.write(f"CICLO {ciclo}\n")
        f.write("ESTÁGIOS:\n")
        nomes = ["IF", "ID", "EX", "MEM", "WB"]
        for i, instr in enumerate(pipeline):
            if instr is not None:
                f.write(f"{nomes[i]}: {instr}\n")
        f.write("\nREGISTRADORES:\n")
        for i in range(32):
            f.write(f"x{i}: {R[i]}\n")
        f.write("\nMEMÓRIA (hex):\n")
        '''for i in range(len(M)):
            if M[i] != 0:
                f.write(f"{i:03X}: {M[i]:02X}\n")'''
        for i in range(0, len(M), 4):  # <-- Loop de 4 em 4 bytes
            word_bytes = M[i:i + 4]
            if len(word_bytes) == 4:
                word_value = int.from_bytes(word_bytes, "little")
                if word_value != 0:
                    f.write(f"0x{i:03X}: 0x{word_value:08X}\n")


        f.write("\n" + "="*40 + "\n")

def resolver_destino(instr):
    if "label" in instr and instr["label"] in labels:
        return labels[instr["label"]]
    return pc + instr["imm"]

def avancar_ciclo():
    global ciclo, pipeline, pc
    ciclo += 1

    # Se a instrução no estágio ID for uma branch, não avança o PC
    #branch
    if pipeline[1] is not None:
        instr = decodificar(pipeline[1])
        if instr["op"] in ["beq", "bne", "blt", "bge", "bltu", "bgeu","bgt"]:
            #print(f"Branch detectada: {instr['op']} de {instr['rs1']} e {instr['rs2']}")
            #print(f"Registradores: R[{instr['rs1']}] = {R[instr['rs1']]}, R[{instr['rs2']}] = {R[instr['rs2']]}")
            if instr["op"] == "beq" and R[instr["rs1"]] == R[instr["rs2"]]:
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "bne" and R[instr["rs1"]] != R[instr["rs2"]]:
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "blt" and R[instr["rs1"]] < R[instr["rs2"]]:
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "bge" and R[instr["rs1"]] >= R[instr["rs2"]]:
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "bltu" and (R[instr["rs1"]] & 0xFFFFFFFF) < (R[instr["rs2"]] & 0xFFFFFFFF):
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "bgeu" and (R[instr["rs1"]] & 0xFFFFFFFF) >= (R[instr["rs2"]] & 0xFFFFFFFF):
                pc = resolver_destino(instr)
                pipeline[0] = "nop"  # Limpa o estágio IF após branch
            elif instr["op"] == "bgt" and R[instr["rs1"]] > R[instr["rs2"]]:
                pc = resolver_destino(instr)
                pipeline[0] = "nop"
        elif instr["op"] == "jalr":
            #print(f"JALR detectada: {instr['op']} de {instr['rs1']}")
            pc = R[instr["rs1"]] + instr["imm"]
            pipeline[0] = "nop"  # Limpa o estágio IF após branch
        elif instr["op"] == "jal":
            #print(f"JAL detectada: {instr['op']} para o rótulo {instr['label']}")
            pc = resolver_destino(instr)
            pipeline[0] = "nop"  # Limpa o estágio IF após branch
        elif instr["op"] == "j":
            # print(f"J detectada: {instr['op']} para o rótulo {instr['label']}")
            pc = resolver_destino(instr)
            pipeline[0] = "nop"  # Limpa o estágio IF após branch
                    
    # executa instrução no estágio EX
    executar_instrucao(pipeline[2])

    # avança pipeline
    pipeline[4] = pipeline[3]
    pipeline[3] = pipeline[2]
    pipeline[2] = pipeline[1]
    pipeline[1] = pipeline[0]
    pipeline[0] = instrucoes[pc] if pc < len(instrucoes) else None
    pc += (pc < len(instrucoes))

    atualizar_pipeline_visual()
    atualizar_registradores_visual()
    atualizar_memoria_visual()
    escrever_saida()

def pegar_arquivo(event=None):
    global instrucoes, pipeline, R, M, ciclo, pc, data,labels

    arq = entry.get()
    if not arq:
        return

    try:
        if arq.endswith(".asm"):
            instrucoes, data, labels = carregar_asm(arq)
        elif arq.endswith(".bin"):
            instrucoes = carregar_bin(arq)
        else:
            print("Formato de arquivo não suportado.")
            return

        R = [0] * 32
        M = bytearray(1000)
        ciclo = 0
        pc = 0
        pipeline = [None] * 5

        atualizar_pipeline_visual()
        atualizar_registradores_visual()
        atualizar_memoria_visual()
        open("saida.out", "w").close()

        print(f"Arquivo '{arq}' carregado com {len(instrucoes)} instruções.")

    except Exception as e:
        print("Erro ao ler arquivo:", e)

# Interface gráfica
janela = tk.Tk()
janela.title("Simulador RISC-V")
janela.geometry("800x400")

janela.columnconfigure(0, weight=1)
janela.rowconfigure(0, weight=1)

frame = tk.Frame(janela)
frame.grid(row=0, column=0, sticky="nsew")

frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)
frame.rowconfigure(2, weight=1)
frame.columnconfigure(2, weight=1)
frame.columnconfigure(3, weight=1)
frame.columnconfigure(4, weight=1)
frame.columnconfigure(5, weight=3)

input_arq = ttk.Label(frame, text="Arquivo:")
input_arq.grid(row=0, column=0)

lblIF = ttk.Label(frame, text="IF")
lblIF.grid(row=1, column=0)

lblID = ttk.Label(frame, text="ID")
lblID.grid(row=1, column=1)

lblEX = ttk.Label(frame, text="EX")
lblEX.grid(row=1, column=2)

lblMEM = ttk.Label(frame, text="MEM")
lblMEM.grid(row=1, column=3)

lblWB = ttk.Label(frame, text="WB")
lblWB.grid(row=1, column=4)

entry = ttk.Entry(frame)
entry.grid(row=0, column=1, columnspan=5, sticky="ew", pady=8, padx=8)
entry.bind("<Return>", pegar_arquivo)

IF = tk.Listbox(frame)
IF.grid(row=2, column=0, sticky="nse")

ID = tk.Listbox(frame)
ID.grid(row=2, column=1, sticky="nsew")

EX = tk.Listbox(frame)
EX.grid(row=2, column=2, sticky="nsew")

MEM = tk.Listbox(frame)
MEM.grid(row=2, column=3, sticky="nsew")

WB = tk.Listbox(frame)
WB.grid(row=2, column=4, sticky="nsew")

registers = tk.Listbox(frame)
registers.grid(row=3, column=0 ,columnspan=3, sticky="nsew", padx=8, pady=8)

memory = tk.Listbox(frame)
memory.grid(row=3, column=3, columnspan=3, sticky="nsew", pady=8, padx=8)

botao = ttk.Button(frame, text="Avançar ciclo", command=avancar_ciclo)
botao.grid(row=1, column=5, sticky="ew", pady=8, padx=8)

janela.mainloop()

