from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pathlib import Path

from ACME_Client import ACMEClient
from DNS_Server import CustomDNSServer
from HTTP_Server_Challenge import power_on_http_server


# ------ GLOBAL VARIABLES ------

key_path = Path(__file__).parent.absolute() / "key.pem"
cert_path = Path(__file__).parent.absolute() / "cert.pem"

# ------ END GLOBAL VARIABLES ------


def generate_csr_and_key(domains):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(NameOID.COMMON_NAME, "dbaciu-eth-netsec"),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    csr_bytes = csr_builder.public_bytes(serialization.Encoding.DER)

    return private_key, csr_bytes


def write_keys_and_certificate(private_key, certificate):
    with open(key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as cert_file:
        cert_file.write(certificate)


def obtain_certificate(args):
    dns_server = CustomDNSServer()

    power_on_http_server()

    for domain in args.domain:
        dns_server.add_A_record(domain, args.record)

    dns_server.start_server()
    print("##########   [Get certificate]   DNS server started   ##########")

    # ##########   [BEGIN Create ACME Client]
    acme_client = ACMEClient(args.dir, dns_server)
    if not acme_client:
        print("##########   [Create ACME Client error]  Process killed     ##########")
        return False
    print("##########   [Create ACME Client]  Successfully!     ##########")
    # ##########   [END Create ACME Client]

    # ##########   [BEGIN Get Directory]
    directory = acme_client.get_directory()
    if not directory:
        print("##########   [Get Directory] Error. Process killed   ##########")
        return False
    print(f"##########   [Get Directory]  Successfully!    Directory={directory}    ##########")
    # ##########   [END Get Directory]

    # ##########   [BEGIN Create ACME Account]
    account = acme_client.create_account()
    if not account:
        print("##########   [Create ACME Account error]  Process killed     ##########")
        return False
    print(f"##########   [Create ACME Account]  Successfully!    Account={account}     ##########")
    # ##########   [END Create ACME Account]

    # ##########   [BEGIN Certificate Order]
    certificate_order, order_url = acme_client.issue_certificate(args.domain)
    if not certificate_order:
        print("##########   [Certificate Order error]  Process killed     ##########")
        return False
    print(f"##########   [Certificate Order]  Successfully!    Certificate Order={certificate_order}     ##########")
    # ##########   [END Certificate Order]

    validate_urls, finalize_url = [], certificate_order["finalize"]

    for auth in certificate_order["authorizations"]:
        certificate_authorization = acme_client.authorize_certificate(auth, args.challenge)
        if not certificate_authorization:
            print("##########   [Certificate Authentication error]  Process killed     ##########")
            return False
        validate_urls.append(certificate_authorization["url"])
        print(f"##########   [Certificate Authentication]    Successfully!     Certificate Authorization={certificate_authorization}     ##########")

    for url in validate_urls:
        certificate_valid = acme_client.validate_certificate(url)
        if not certificate_valid:
            print("##########   [Certificate Validation error]  Process killed     ##########")
            return False
        print(f"##########   [Certificate Validation]    Successfully!     Certificate Validation={certificate_valid}     ##########")

    key, der = generate_csr_and_key(args.domain)
    certificate_url = acme_client.finalize_certificate(order_url, finalize_url, der)
    if not certificate_url:
        print("##########   [Certificate Finalizing error]  Process killed     ##########")
        return False
    print(f"##########   [Certificate Finalizing]    Successfully!     Certificate Finalized={certificate_url}     ##########")

    downloaded_certificate = acme_client.download_certificate(certificate_url)
    if not downloaded_certificate:
        print("##########   [Certificate Downloading error]  Process killed     ##########")
        return False
    print(f"##########   [Certificate Downloading]    Successfully!     Certificate Downloaded={downloaded_certificate}     ##########")

    print("##########   [Certificate writing to disk] ... ##########")
    write_keys_and_certificate(key, downloaded_certificate)

    if args.revoke:
        print("##########   [Revoking Certificate] ... ##########")
        crypto_certificate = x509.load_pem_x509_certificate(downloaded_certificate)
        acme_client.revoke_certificate(crypto_certificate.public_bytes(serialization.Encoding.DER))
        print("##########   [Certificate Revoked] DONE ! ##########")
