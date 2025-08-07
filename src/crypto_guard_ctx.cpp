#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class StreamGuard {
public:
    StreamGuard(std::iostream &stream, std::string_view name) : stream_(stream) {
        if (!stream_.good())
            throw std::runtime_error(std::string(name) + " stream is in bad state");
        pos_ = stream_.tellg();
        if (pos_ == std::streampos(-1))
            throw std::runtime_error("Can't determine " + std::string(name) + " stream position");
    }

    ~StreamGuard() {
        stream_.clear();      // Сброс ошибок перед выходом
        stream_.seekg(pos_);  // Восстановление позиции
    }

    class bad_stream : public std::runtime_error {
        using runtime_error::runtime_error;
    };

private:
    std::iostream &stream_;
    std::streampos pos_;
};

std::string get_openssl_error() {
    std::vector<char> buf(256);
    unsigned long err_code;
    std::string error_msg;

    while ((err_code = ERR_get_error()) != 0) {
        ERR_error_string_n(err_code, buf.data(), sizeof(buf));
        if (!error_msg.empty()) {
            error_msg += "; ";
        }
        error_msg += buf.data();
    }

    return error_msg.empty() ? "Unknown OpenSSL error" : error_msg;
}

class CryptoGuardCtx::Impl {

public:
    Impl() {
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
    }

    ~Impl() { EVP_cleanup(); }

    struct EVP_Cipher_Deleter {
        void operator()(EVP_CIPHER_CTX *ptr) const { EVP_CIPHER_CTX_free(ptr); }
    };

    struct EVP_MD_Deleter {
        void operator()(EVP_MD_CTX *ptr) const { EVP_MD_CTX_free(ptr); }
    };

    // Приватный интерфейс для нового алгоритма шифрования пары чисел

    void ProcessFile(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                     CryptoGuardCtx::CifherMode mode);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    void ProcessCifher(std::unique_ptr<EVP_CIPHER_CTX, EVP_Cipher_Deleter> ctx, std::iostream &input,
                       std::iostream &output);
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

void CryptoGuardCtx::Impl::ProcessFile(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                                       CryptoGuardCtx::CifherMode mode) {

    {
        StreamGuard guard_in(inStream, "Input");
        StreamGuard guard_out(outStream, "Output");
    }

    ERR_clear_error();

    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = static_cast<int>(mode);

    std::unique_ptr<EVP_CIPHER_CTX, EVP_Cipher_Deleter> evp_ctx{EVP_CIPHER_CTX_new()};

    // Инициализируем cipher
    EVP_CipherInit_ex(evp_ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

    ProcessCifher(std::move(evp_ctx), inStream, outStream);
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {

    {
        StreamGuard guard_in(inStream, "Input");
    }

    ERR_clear_error();

    const EVP_MD *algorithm = EVP_sha256();

    if (!algorithm)
        throw std::runtime_error("Failed to get hash algorithm: " + get_openssl_error());

    std::unique_ptr<EVP_MD_CTX, EVP_MD_Deleter> mdctx{EVP_MD_CTX_new()};

    if (!mdctx)
        throw std::runtime_error("Failed to create EVP_MD_CTX: " + get_openssl_error());

    if (EVP_DigestInit_ex(mdctx.get(), algorithm, nullptr) != 1)
        throw std::runtime_error("Failed to initialize digest: " + get_openssl_error());

    std::vector<unsigned char> buffer(1024);

    while (true) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        const auto bytes_read = inStream.gcount();

        if (bytes_read > 0 && EVP_DigestUpdate(mdctx.get(), buffer.data(), bytes_read) != 1)
            throw std::runtime_error("Failed to update digest: " + get_openssl_error());

        // Проверяем состояние после чтения
        if (inStream.eof())
            break;

        if (!inStream.good())
            throw std::runtime_error("Stream read operation failed");
    }

    // 4. Получаем финальный хеш
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx.get(), hash, &hash_len) != 1)
        throw std::runtime_error("Failed to finalize digest: " + get_openssl_error());

    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; i++) {
        oss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return oss.str();
}

void CryptoGuardCtx::Impl::ProcessCifher(std::unique_ptr<EVP_CIPHER_CTX, EVP_Cipher_Deleter> ctx, std::iostream &input,
                                         std::iostream &output) {

    size_t buf_size = 1024;
    std::vector<unsigned char> outBuf(buf_size + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(buf_size);
    int outLen;

    while (true) {
        input.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        const auto bytes_read = input.gcount();

        // Если прочитали хоть что-то
        if (bytes_read > 0) {
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytes_read)))
                throw std::runtime_error("OpenSSL CipherUpdate operation failed: " + get_openssl_error());

            output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

            if (!output.good())
                throw std::runtime_error("Stream write operation failed");
        } else {
            break;
        }

        // Проверяем состояние после чтения
        if (input.eof())
            break;

        if (!input.good()) {
            throw std::runtime_error("Stream read operation failed");
        }
    }

    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen))
        throw std::runtime_error("OpenSSL CipherFinal operation failed: " + get_openssl_error());

    output.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    if (!output.good())
        throw std::runtime_error("Stream write operation failed");
};

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0)
        throw std::runtime_error{"Failed to create a key from password" + get_openssl_error()};

    return params;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

// API
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->ProcessFile(inStream, outStream, password, CifherMode::ENCRYPT);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->ProcessFile(inStream, outStream, password, CifherMode::DECRYPT);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
