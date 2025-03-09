import os
import ecdsa
import hashlib
import base58
import codecs
import time
import concurrent.futures

# Fonction pour charger les adresses Bitcoin à partir d'un fichier
def load_addresses():
    with open('C:\\Users\\james\\Desktop\\2009 btc\\btc.txt', 'r') as file:
        return set(line.strip() for line in file)  # Utiliser un set pour des recherches plus rapides

# Fonction pour générer une clé publique non compressée à partir d'une clé privée
def private_key_to_public_key(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    # Clé publique non compressée (prefixe \04)
    uncompressed_public_key = b'\04' + verifying_key.to_string()
    return uncompressed_public_key

# Fonction pour générer une adresse Bitcoin à partir d'une clé publique
def public_key_to_address(public_key):
    # Étape 1: Hachage SHA-256
    sha256_public_key = hashlib.sha256(public_key).digest()
    # Étape 2: Hachage RIPEMD-160
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_public_key)
    hashed_public_key = ripemd160.digest()

    # Étape 3: Ajouter le byte de version (0x00 pour l'adresse Bitcoin principale)
    network_byte = b'\x00' + hashed_public_key

    # Étape 4: Double SHA-256 pour obtenir le checksum
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]

    # Étape 5: Ajouter le checksum à l'adresse
    binary_address = network_byte + checksum

    # Étape 6: Encoder l'adresse en Base58
    address = base58.b58encode(binary_address)
    return address.decode('utf-8')

# Fonction pour générer une clé privée aléatoire
def generate_private_key():
    random_bytes = os.urandom(32)
    private_key = codecs.encode(random_bytes, 'hex').decode('utf-8')
    return private_key

# Fonction pour vérifier si l'adresse générée correspond à une adresse dans btc_addresses
def match_addresses(private_key, btc_addresses):
    public_key = private_key_to_public_key(private_key)
    generated_address = public_key_to_address(public_key)
    return generated_address if generated_address in btc_addresses else None

# Fonction pour sauvegarder la clé privée et l'adresse trouvée dans le fichier found.txt
def save_found(private_key, found_address):
    with open('found.txt', 'a') as file:
        file.write(f"Private Key: {private_key}, Address: {found_address}\n")

# Fonction pour afficher l'état du processus
def display_status(private_key, address, total_checked, found_count, total_addresses, generated_count):
    print(f"\n[Checked: {total_checked}/{total_addresses}]")
    print(f"[Generated: {generated_count}]")
    print("=========================================")
    print(f"Private Key: {private_key}")
    print(f"Generated Address: {address}")
    print(f"Found Matches: {found_count}")
    print("=========================================\n")

# Fonction principale
def main():
    btc_addresses = load_addresses()  # Charger les adresses depuis le fichier et les mettre dans un set
    total_addresses = len(btc_addresses)  # Nombre total d'adresses à vérifier
    total_checked = 0
    found_count = 0
    generated_count = 0  # Nombre d'adresses générées

    start_time = time.time()  # Temps de départ pour mesurer la performance

    # Utiliser ThreadPoolExecutor pour vérifier les adresses en parallèle
    with concurrent.futures.ThreadPoolExecutor() as executor:
        while True:
            # Générer un lot de clés privées aléatoires (par exemple, 100 clés privées)
            private_keys = [generate_private_key() for _ in range(100)]  # Générer 100 clés privées

            # Utiliser l'exécuteur pour vérifier les adresses en parallèle
            futures = [executor.submit(match_addresses, private_key, btc_addresses) for private_key in private_keys]

            for private_key, future in zip(private_keys, concurrent.futures.as_completed(futures)):
                found_address = future.result()
                if found_address:
                    found_count += 1
                    save_found(private_key, found_address)  # Utiliser la bonne clé privée ici
                    print(f"*** Match trouvé ! *** Clé privée : {private_key}, Adresse : {found_address}\n")

                # Mettre à jour les compteurs et afficher l'état
                total_checked += 1
                generated_count += 1
                display_status(private_key, found_address, total_checked, found_count, total_addresses, generated_count)

            # Vérification des performances chaque seconde
            elapsed_time = time.time() - start_time
            if elapsed_time >= 1:
                print(f"Adresses vérifiées dans la dernière seconde : {total_checked}")
                start_time = time.time()  # Réinitialiser le temps

if __name__ == "__main__":
    main()
