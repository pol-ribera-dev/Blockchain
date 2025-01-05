import sympy
import hashlib

class rsa_key:
    def __init__(self,bits_modulo=2048,e=2**16+1):
        '''
        genera una clave RSA (de 2048 bits y exponente p´ublico 2**16+1 por defecto)
        '''

        self.publicExponent = e

        a = 2 ** int((bits_modulo - 1) / 2)
        b = 2 ** int(bits_modulo / 2)

        self.primeP = sympy.randprime(a, b)
        self.primeQ = sympy.randprime(a, b)

        euler = (self.primeP-1)*(self.primeQ-1)
        self.privateExponent = pow(e, -1, euler)



        self.modulus = self.primeP * self.primeQ

        self.privateExponentModulusPhiP = self.privateExponent % (self.primeP - 1)

        self.privateExponentModulusPhiQ = self.privateExponent % (self.primeQ - 1)

        self.inverseQModulusP = pow(self.primeQ, -1, self.primeP)


    def __repr__(self):
        return str(self.__dict__)
    def sign(self,message):
        '''
        Salida: un entero que es la firma de "message" hecha con la clave RSA usando el TCR
        '''
        dp = self.privateExponent % (self.primeP - 1)
        dq = self.privateExponent % (self.primeQ - 1)

        a = pow(message, dp, self.primeP)
        b = pow(message, dq, self.primeQ)

        q_inv = sympy.mod_inverse(self.primeQ, self.primeP)
        p_inv = sympy.mod_inverse(self.primeP, self.primeQ)

        return (a * self.primeQ * q_inv + b * self.primeP * p_inv) % self.modulus
    def sign_slow(self,message):
        '''
        Salida: un entero que es la firma de "message" hecha con la clave RSA sin usar el TCR
        '''
        return pow(message, self.privateExponent, self.modulus)

class rsa_public_key:
    def __init__(self, publicExponent=1, modulus=1):
        '''
        genera la clave p´ublica RSA asociada a la clave RSA "rsa_key"
        '''
        self.publicExponent = publicExponent
        self.modulus = modulus

    def __repr__(self):
        return str(self.__dict__)
    def verify(self, message, signature):
        '''
        Salida: el booleano True si "signature" se corresponde con la
        firma de "message" hecha con la clave RSA asociada a la clave
        p´ublica RSA;
        el booleano False en cualquier otro caso.
        '''

        message_hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
        signature_hash = pow(signature, self.publicExponent, self.modulus)
        return signature_hash == message_hash



class transaction:
    def __init__(self, message = 0, RSAkey = 0):
        '''
        genera una transaccion firmando "message" con la clave "RSAkey"
        '''
        if RSAkey == 0:
            self.public_key = 0
            self.message = 0
            self.signature = 0
        else:
            self.public_key = rsa_public_key(RSAkey.publicExponent, RSAkey.modulus)
            self.message = message
            self.signature = RSAkey.sign(message)

    def __repr__(self):
        return str(self.__dict__)

    def verify(self):
        '''
        Salida: el booleano True si "signature" se corresponde con la
        firma de "message" hecha con la clave RSA asociada a la clave
        p´ublica RSA;
        el booleano False en cualquier otro caso.
        '''
        decrypted = pow(self.signature, self.public_key.publicExponent, self.public_key.modulus)
        return self.message == decrypted

    def from_dictionary(self, transaccion):
        """
        transaccion = {
        ’public_key’: {
        ’publicExponent’: 65537,
        ’modulus’: 77268792373531530874859775898227231886721361866344308896457165466217957463548},
        ’message’: 1111111,
        ’signature’: 4848031355983687005831589412107814535662119655983142282793959266002525538316655}
        """
        self.public_key = rsa_public_key(publicExponent=transaccion['public_key']['publicExponent'], modulus=transaccion['public_key']['modulus'])
        self.message = transaccion['message']
        self.signature = transaccion['signature']

class block:
    def __init__(self):

        '''
        crea un bloque (no necesariamente v´alido)
        '''
        self.block_hash = 0
        self.previous_block_hash = 0
        self.transaction = 0
        self.seed = 0
    def __repr__(self):
        return str(self.__dict__)
    def genesis(self,transaction):
        '''genera el primer bloque de una cadena con la transacci´on "transaction"
                que se caracteriza por:
                - previous_block_hash=0
                - ser v´alido'''
        self.transaction = transaction
        self.previous_block_hash = 0
        self.seed = 1
        while True:
            self.seed += 1
            self.block_hash = self.generar_hash()
            if self.block_hash < pow(2, 256 - 16):
                break
        return self


    def next_block(self, transaction):
        '''
        genera un bloque v´alido seguiente al actual con la transacci´on "transaction"
        '''
        self.transaction = transaction
        self.seed = 1
        while True:
            self.seed += 1
            self.block_hash = self.generar_hash()
            if self.block_hash < pow(2, 256-16):
                break
        return self

    def generar_hash(self):
        entrada = str(self.previous_block_hash)
        entrada = entrada + str(self.transaction.public_key.publicExponent)
        entrada = entrada + str(self.transaction.public_key.modulus)
        entrada = entrada + str(self.transaction.message)
        entrada = entrada + str(self.transaction.signature)
        entrada = entrada + str(self.seed)
        entrada = int(hashlib.sha256(entrada.encode()).hexdigest(), 16)
        return entrada

    def verify_block(self):
        '''Verifica si un bloque es v´alido:
        -Comprueba que el hash del bloque anterior cumple las condiciones exigidas
        -Comprueba que la transacci´on del bloque es v´alida
        -Comprueba que el hash del bloque cumple las condiciones exigidas
        Salida: el booleano True si todas las comprobaciones son correctas;
        el booleano False en cualquier otro caso.'''
        d = 16
        print("uno", self.generar_hash())
        print("dos", self.block_hash)
        return self.transaction.verify() and self.block_hash < pow(2, 256-d) and self.previous_block_hash < pow(2, 256-d) and self.block_hash == self.generar_hash()


    def from_dictionary(self, bloque):
        """
        bloque = {
        ’block_hash’: 611227525515763553892040764593246705224095844323849655584941894507859918,
        ’previous_block_hash’: 860009111636437550099323966792787928396638877763118311905514989098990’transaction’: {
        ’public_key’: {
        ’publicExponent’: 65537,
        ’modulus’: 8630046192387106941807604362020441904807683470496793476434516960168353410},
        ’message’: 1111111111111111111111111111111111111,
        ’signature’: 356837000610140335661652832488149719307360962608450865619567471410525725851},
        ’seed’: 15788038037054404536350655987002785795816312452536967153872713568114538152952}
        """
        self.block_hash = bloque['block_hash']
        self.previous_block_hash = bloque['previous_block_hash']
        transaccion_aux = transaction()
        transaccion_aux.from_dictionary(bloque['transaction'])
        self.transaction = transaccion_aux
        self.seed = bloque['seed']


class block_chain:
    def __init__(self,transaction=0):

        '''genera una cadena de bloques que es una lista de bloques,
        el primer bloque es un bloque "genesis" generado amb la transacci´o "transaction"'''
        self.list_of_blocks = []
    def __repr__(self):
        return str(self.__dict__)

    def add_block(self,transaction):
        '''
        a~nade a la cadena un nuevo bloque v´alido generado con la transacci´on "transaction"
        '''
        bloc = block()
        if len(self.list_of_blocks) == 0:
            self.list_of_blocks.append(bloc.genesis(transaction))
        else:
            bloc.previous_block_hash =  self.list_of_blocks[-1].block_hash
            self.list_of_blocks.append(bloc.next_block(transaction))

    def verify(self):
        '''
        verifica si la cadena de bloques es v´alida:
        - Comprueba que todos los bloques son v´alidos
        - Comprueba que el primer bloque es un bloque "genesis"
        - Comprueba que para cada bloque de la cadena el siguiente es correcto
        Salida: el booleano True si todas las comprobaciones son correctas;
        en cualquier otro caso, el booleano False y un entero
        correspondiente al ´ultimo bloque v´alido
        '''
        """if not((isgen(self.list_of_blocks[0]) and ver) or len(self.list_of_blocks) == 0):
            return False"""
        anterior = 0
        for block in self.list_of_blocks:
            if not (block.previous_block_hash == anterior and block.verify_block()):
                return False
            anterior = block.block_hash
        return True

    def from_dictionary(self, lista_de_bloques):

        """lista_de_bloques={
        ’list_of_blocks’:
        [
        {’block_hash’: 438706950606371822348686247462944262134905088999967426,
        ’previous_block_hash’: 0,
        ’transaction’: {’public_key’: {’publicExponent’: 65537,
        ’modulus’: 3508702911114772477700098583160780159},
        ’message’: 1111111111111111111111111111111111111,
        ’signature’: 332227860166626417010520625676972266506588923498746
        },
        ’seed’: 30375809828338577849000370815876946005956863228327241857747841325460539099376
        },
        {’block_hash’: 118937117756121245414585385816047931576536827076435985509379583936567275586,{’block_hash’: 435041778968092905364474619022589453690222734303800866991470949446770182979,{’block_hash’: 278792726160560451158678572042505587638954710660454744060308266170299446132,{’block_hash’: 250872889707793976966219660933458705965282691125212532154197547013416918695,...
        ]
        }"""

        aux = []
        for i in lista_de_bloques['list_of_blocks']:
            bloque = block()
            bloque.from_dictionary(i)
            aux.append(bloque)
        self.list_of_blocks = aux

