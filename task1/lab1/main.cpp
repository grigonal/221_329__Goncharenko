#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include <QString>
#include <QByteArray>
#include <QDebug>
#include <QCryptographicHash>
#include <QBuffer>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>

struct LibraryRecord {
    QString sha256;
    QString bookTitle;
    QString timestamp;
    QString cardNumber;
};


std::string sha256Base64(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string getCurrentDateTime() {
    time_t now = time(nullptr);
    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", gmtime(&now));
    return std::string(buf);
}



int decryptByteArray(const QByteArray &aes256_key, const QByteArray &hexEncryptedBytes, QByteArray &decryptedBytes) {
    unsigned char key[32] = {0};
    memcpy(key, aes256_key.data(), 32);
    QByteArray iv_hex("5ffc6cea35a6a83dcb8d3e3e8201c9ce");
    QByteArray iv_ba = QByteArray::fromHex(iv_hex);
    unsigned char iv[16] = {};
    memcpy(iv, iv_ba.data(), 16);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL)) {
        qDebug() << "*** EVP_DecryptInit_ex2() ERROR ***";
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    qDebug() << "*** EVP_DecryptInit_ex2() OK ***";
#define BUF_LEN 256
    unsigned char encrypted_buf[BUF_LEN] = {0}, decrypted_buf[BUF_LEN] = {0};
    int encr_len, decr_len;
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    QDataStream encrypted_stream(encryptedBytes);
    decryptedBytes.clear();

    QBuffer decrypted_buffer(&decryptedBytes);
    decrypted_buffer.open(QIODevice::WriteOnly);
    encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    while (encr_len > 0) {
        if (!EVP_DecryptUpdate(ctx, decrypted_buf, &decr_len, encrypted_buf, encr_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), decr_len);
        encr_len = encrypted_stream.readRawData(reinterpret_cast<char*>(encrypted_buf), BUF_LEN);
    }
    int templen;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_buf, &templen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    decrypted_buffer.write(reinterpret_cast<char*>(decrypted_buf), templen);
    decrypted_buffer.close();
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}



std::vector<LibraryRecord> parseRecords(const QString& data) {
    std::vector<LibraryRecord> records;
    QTextStream stream(const_cast<QString*>(&data));
    QString line;

    while (stream.readLineInto(&line)) {
        if (line.isEmpty() || line == "---") continue;

        LibraryRecord record;
        record.sha256 = line;

        if (!stream.readLineInto(&record.bookTitle) ||
            !stream.readLineInto(&record.timestamp) ||
            !stream.readLineInto(&record.cardNumber)) {
            qCritical() << "Error: Wrong format.";
            break;
        }

        records.push_back(record);
    }

    return records;
}

QString calculateSha256(const QString& bookTitle, const QString& timestamp, const QString& cardNumber) {
    QString data = bookTitle + timestamp + cardNumber;
    QByteArray hash = QCryptographicHash::hash(data.toUtf8(), QCryptographicHash::Sha256);
    return QString(hash.toHex());
}

void displayRecords(const std::vector<LibraryRecord>& records) {
    for (const auto& record : records) {
        QString calculatedHash = calculateSha256(record.bookTitle, record.timestamp, record.cardNumber);

        // Проверка соответствия хеша
        if (calculatedHash != record.sha256) {
            qDebug().noquote() << "\033[31m"  // Красный цвет
                               << "!!! Ошибка: запись некорректна !!!\n"
                               << "!!!SHA-256: " << record.sha256 << "\n"
                               << "!!!Название книги: " << record.bookTitle << "\n"
                               << "!!!Дата и время: " << record.timestamp << "\n"
                               << "!!!Номер читательского билета: " << record.cardNumber
                               << "!!!\033[0m";  // Сброс цвета
        } else {
            qDebug() << "SHA-256:" << record.sha256;
            qDebug() << "Название книги:" << record.bookTitle;
            qDebug() << "Дата и время:" << record.timestamp;
            qDebug() << "Номер читательского билета:" << record.cardNumber;
        }
        qDebug() << "---------------------------------------";
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);

    QByteArray key = "this_is_a_secret_key_32bytes_long";  // Ключ (32 байта)




    QFile file(":/data.txt");
    file.open(QFile::ReadOnly);
    if (!file.isOpen()) {
        qDebug() << file.errorString();
        return -1;
    }
    QByteArray hexEncBytes = file.readAll();
    file.close();

    QByteArray decryptedData;
    decryptByteArray(key, hexEncBytes, decryptedData);



    std::vector<LibraryRecord> records = parseRecords(decryptedData);
    if (records.empty()) {
        qDebug() << "Нет данных для отображения.";
        return 0;
    }

    qDebug() << "Данные библиотеки:";
    qDebug() << "---------------------------------------";
    displayRecords(records);

    return 0;
}
