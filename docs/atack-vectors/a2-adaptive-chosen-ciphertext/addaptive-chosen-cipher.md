# Adaptive Chosen-Ciphertext Attack

Modyfikacja bajtu ciphertextu daje kontrolowaną zmianę plaintextu bez znajomości klucza

**Typ ataku:** Adaptive Chosen-Ciphertext Attack (CCA2), partial plaintext recovery

**Źródło:** [Implementation of Chosen-Ciphertext Attacks against PGP and GnuPG](https://www.schneier.com/academic/archives/2002/01/implementation_of_ch.html), [An Attack on CFB Mode Encryption As Used By OpenPGP](https://eprint.iacr.org/2005/033.pdf)

## Dane techniczne

Wersja gpg: 
```
…/docs/atack-vectors master ? ❯ gpg --version
gpg (GnuPG) 2.4.9
```
Wersja age:
```
…/docs/atack-vectors master ? ✗ age --version
1.3.1
```

## Scenariusz ataku

Atakujący przechwytując zaszyfrowany plik z trybem CFB. Następnie poprzez modyfikację plaintextu za pomocą operacji XOR może on otrzymać modyfikację plaintextu która będzie przechodzić quick-check podczas próby deszyfrowania. Atakujący wiec przystępuje do odszyfrowywania tak zmienionego cypher text wiedząc, że operacja XOR została nanesiona na odszyfrowany tekst:

```
plaintext[16+i]  =  ct[34+i]  XOR  E(ct[18:34])[i]
                    ↑              ↑
                 znany             NIEZNANY
                 atakującemu      (wymaga klucza)

plaintext'[16+i]  =  (ct[34+i] XOR 0x20)  XOR  E(ct[18:34])[i]  =   ct[34+i]  XOR  E(ct[18:34])[i]  XOR 0x20  =   plaintext[16+i]  XOR  0x20
```

Znając tą zależność można zacząc zgadywać co jest faktycznie w zaszyfrowanym pliku. Jeżeli atakujący wybierze modyfikację o 0x20 to zamienia na poczatku `ct[34] ^= 0x20` i odpytuje jakąś formę wyroczni (np serwis mailowy) co zostanie zwrócone. Oracle zwraca: `wyjście'[8] = 0x6B ('k')` dzięki temu atakujący może obliczyć: `wyjście[8] = wyjście'[8] XOR delta = 0x6B XOR 0x20 = 0x4B = 'K'`.

### Realizacja ataku dla pgp

Rozpoczynamy od zaszyfrowania tajnej wiadomości z odpowiednimi flagami:

```
…/docs/atack-vectors master ? ❯ echo "TAJNY DOKUMENT: klucz dostepu XK-7734-ALFA" | \
gpg --symmetric --cipher-algo AES128 --compress-algo none --s2k-digest-algo SHA1 --allow-old-cipher-algos --batch --passphrase "demo" --output target.gpg
```

Następnie znając strukturę szyfrowania pliku pgp z trybem CFB:
```
ct[0:16]  = E_key(IV=0x00×16) XOR prefix_losowy → PREFIX
ct[16:18] = E_key(ct[0:16]) XOR prefix[14:16] → QUICK CHECK
ct[18:34] = E_key(ct[2:18]) XOR plaintext[0:16] → BLOK 0 plaintextu
ct[34:50] = E_key(ct[18:34]) XOR plaintext[16:32] → BLOK 1 plaintextu
ct[50:66] = E_key(ct[34:50]) XOR plaintext[32:48] → BLOK 2 plaintextu
```

Wiedząc jakie fragmenty cyphertextu odpowiadają za jakie elemty wiemy że musimy modyfikować bajty od 34 w górę aby nie wpłynąć na modyfikację elementów cyphertextu, które odpowiadają za qucik check. Wiedząc to możemy za pomoca skryptu (z symulowaną oracle) zgadaywać co znajduje się wenwnątrz zaszyfrowanego pliku:

```
…/docs/atack-vectors master ? ❯ python3 cca.py
Baseline — oryginalny plaintext

  QC: PASS  exit=0  plaintext: 'TAJNY DOKUMENT: klucz dostepu XK-7734-ALFA'

Oracle PASS vs FAIL

  Modyfikacja ct[16] (Quick Check) → FAIL
  ct[16] ^= 0xFF: QC=PASS  exit=2  bad_session_key=True

  Modyfikacja ct[34] (blok 1) → PASS (QC niezmienione)
  ct[34] ^= 0x20: QC=PASS  exit=2 (MDC fail)  — ale przy ignore-mdc: plaintext dostępny

  i  ct_idx  true    oracle  guessed  match
  ──────────────────────────────────────────
  0  ct[34]  'K'     'k'     'K'      OK
  1  ct[35]  'U'     'u'     'U'      OK
  2  ct[36]  'M'     'm'     'M'      OK
  3  ct[37]  'E'     'e'     'E'      OK
  4  ct[38]  'N'     'n'     'N'      OK
  5  ct[39]  'T'     't'     'T'      OK
  6  ct[40]  ':'     '\x1a'  ':'      OK
  7  ct[41]  ' '     '\x00'  ' '      OK

  Odgadniete bajty: 'KUMENT: '
  Prawdziwe bajty: 'KUMENT: '
  Dokladnosc: 8/8
  Zapytania oracle: 11
```

Wartości '\x1a' i '\x00' w kolumnie oracle (nie ':' i ' ') to efekt error propagation CFB. Zmiana `ct[34+i]` niszczy cały blok `ct[18:34]` jako IV dla bloku 2, dlatego bajty po zmodyfikowanym bloku są "śmieciami". Ale bajty przed nim (blok 0) i same odgadywane bajty pozostają poprawnie zakodowane. Możemy je odgadnąć przez zastosowanie operacji XOR z 0x20 na '\x1a' i '\x00' otrzymując znaki ':' i ' '.

Ważna uwaga aby cały atak był przeprowadzony poprawnie to oracle stosuje flagę `--ignore-mdc-error` lub inną metodę ignornowania błędów MDC.

### Realizacja ataku dla age

Tak jak w przypadku pgp szyfrujemy tajną wiadomość:

```
…/docs/atack-vectors master ? ❯ age-keygen -o age.key
Public key: age1l4juzmxes92t65jd905vu7nnkcm28jxx8g7nq4ecef04jee7ag3ssuap30

…/docs/atack-vectors master ? ❯ age -r $(age-keygen -y age.key) -o target.age secret.txt
```

Tu ponownie modyfikujemy bity w cyphertexcie i próbójemy odszyfrować tak zmieniony plik. age zwraca kod błedu 1, odmowy odszyfrowania, z komunikatem `age: error: no identity matched any of the recipients`. Na wyjściu nie jest nic zwracane.

## Wnioski

gpg ma dwa mechanizmy obrony przed modyfikacją cyphertextu quick check i MDC. Quick check nie wykrywa wprowadzanych manipulacji bo modyfikujemy `ct[34+]`, a nie `ct[16:18]`. MDC wykrywa te modyfikacje ale tylko jeśli klient sprawdza i reaguje na zwracany błąd. W 2018 roku większość klientów emailowych ignorowała ten kod wyjścia. 
Jest to wada architektury gpg, która rozdziela autentykację od mechanizmu szybkiej weryfikacji.

age używa ChaCha20-Poly1305 (AEAD), który jest z definicji IND-CCA2 bezpieczny. Każda modyfikacja ciphertextu powoduje weryfikację tagu Poly1305, która zawsze kończy się odmową zwrócenia plaintextu.


