# people_card

- Генерация NFT ID: Для каждого сертификата создается уникальный идентификатор на основе данных сертификата.
- Генерация RSA ключей: Система создает приватный и публичный ключи для подписи и верификации.
- Подпись сертификата: Сертификат подписывается приватным ключом.
- Верификация подписи: Публичный ключ используется для проверки подлинности сертификата.

Для реализации поддержки аттестатов (credentials) и доверенных анкор (trusted anchors) в NFT сертификатах, а также соответствия стандартам W3C Verifiable Credentials (VC), потребуется расширить систему, включив следующие элементы:

Проверка аттестатов (Verifiable Credentials):

Аттестаты — это утверждения о субъекте (например, имя, курс, дата завершения), подписанные проверяемой стороной (Issuer).
Для проверки аттестатов используется проверка цифровой подписи, проверка валидности данных, а также соответствие аттестатов доверенным анкорам.
Доверенные анкорные сущности (trusted anchors):

Доверенные анкорные сущности — это организации или субъекты, которым доверяет пользователь. Они подписывают аттестаты (например, учебное заведение или организация, которая подтверждает выданный сертификат).
Анкорными сущностями могут быть публичные ключи организаций, хранящиеся в виде DID (Decentralized Identifier).

Дополнительные поля из W3C Verifiable Credentials:

 - @context: Определяет контекст данных, включая стандарты W3C.
 - type: Определяет тип аттестата, например, "VerifiableCredential".
 - issuer: Субъект (например, организация), который выдал аттестат.
 - credentialSubject: Субъект, к которому относится аттестат (например, имя студента, который получил сертификат).
 - issuanceDate: Дата выдачи аттестата.
 - expirationDate (опционально): Дата истечения срока действия аттестата.
 - proof: Доказательство, которое включает цифровую подпись аттестата.

# Описание NFT механик
Шаги для проверки:
1. Проверка цифровой подписи аттестата:
Извлекается proof (доказательство) из данных аттестата.
Проверяется подпись с использованием публичного ключа issuer (выдавшей организации).
Используем jws (JSON Web Signature) или другую схему для проверки.

2. Верификация доверенных анкорных сущностей:
Trusted anchors — это проверенные источники данных, например, университеты или организации.
Для этого необходимо поддерживать список доверенных DID или публичных ключей, которые могут подписывать аттестаты.
DID может быть верифицирован через цепочки доверия или с использованием блокчейна.

3. Проверка даты и валидности аттестата:
Проверяется дата истечения срока действия аттестата, если она указана.
Проверяются обязательные поля, такие как субъект, дата выдачи и другие данные.
