aea encrypt -i plaintext -o vector.0.aea -profile 0 -sign-priv test_asymm
aea encrypt -i plaintext -o vector.1.aea -profile 1 -key test_symm
aea encrypt -i plaintext -o vector.2.aea -profile 2 -key test_symm -sign-priv test_asymm
# TODO: consider using different keypair for recipient
aea encrypt -i plaintext -o vector.3.aea -profile 3 -recipient-pub test_asymm.pub
aea encrypt -i plaintext -o vector.4.aea -profile 4 -recipient-pub test_asymm.pub -sign-priv test_asymm
aea encrypt -i plaintext -o vector.5.aea -profile 5 -password test_password
