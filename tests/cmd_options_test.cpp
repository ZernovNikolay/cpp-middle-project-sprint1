#include "cmd_options.h"
#include "gtest/gtest.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;

// Вспомогательная функция для создания argv из вектора строк
std::pair<int, char **> create_argv(const std::vector<std::string> &args) {
    int argc = args.size();
    char **argv = new char *[argc];

    for (int i = 0; i < argc; ++i) {
        argv[i] = new char[args[i].size() + 1];
        strcpy(argv[i], args[i].c_str());
    }

    return {argc, argv};
}

// Вспомогательная функция для освобождения памяти argv
void free_argv(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        delete[] argv[i];
    }
    delete[] argv;
}

TEST(ProgramOptions, HelpOption) {
    auto [argc, argv] = create_argv({"program", "--help"});

    testing::internal::CaptureStdout();
    ProgramOptions options;

    EXPECT_EXIT(options.Parse(argc, argv), ::testing::ExitedWithCode(0),
                ""  // Проверяем наличие текста в выводе
    );

    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("Allowed options") != std::string::npos);

    free_argv(argc, argv);
}

TEST(ProgramOptions, ValidEncryptCommand) {
    auto [argc, argv] = create_argv(
        {"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.enc", "--password", "secret"});

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.enc");
    EXPECT_EQ(options.GetPassword(), "secret");

    free_argv(argc, argv);
}

TEST(ProgramOptions, ValidDecryptCommand) {
    auto [argc, argv] =
        create_argv({"program", "-c", "decrypt", "-i", "input.enc", "-o", "output.txt", "-p", "secret"});

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.enc");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");

    free_argv(argc, argv);
}

TEST(ProgramOptions, ValidChecksumCommand) {
    auto [argc, argv] =
        create_argv({"program", "--command", "checksum", "--input", "data.bin", "--output", "checksum.txt"});

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(argc, argv));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "data.bin");
    EXPECT_EQ(options.GetOutputFile(), "checksum.txt");

    free_argv(argc, argv);
}

TEST(ProgramOptions, MissingRequiredOption) {
    auto [argc, argv] = create_argv({
        "program", "--command", "encrypt", "--input", "input.txt"
        // Нет --output и --password
    });

    ProgramOptions options;

    EXPECT_EXIT(options.Parse(argc, argv), ::testing::ExitedWithCode(1),
                "Error: the option '--output' is required but missing"  // Проверяем наличие текста в выводе
    );

    free_argv(argc, argv);
}

TEST(ProgramOptions, MissingPasswordForEncrypt) {
    auto [argc, argv] = create_argv({
        "program", "--command", "encrypt", "--input", "input.txt", "--output", "output.enc"
        // Нет --password
    });

    ProgramOptions options;

    EXPECT_EXIT(options.Parse(argc, argv), ::testing::ExitedWithCode(1),
                "Error: Password is required for encryption/decryption"  // Проверяем наличие текста в выводе
    );

    free_argv(argc, argv);
}

TEST(ProgramOptions, InvalidCommand) {
    auto [argc, argv] =
        create_argv({"program", "--command", "invalid", "--input", "input.txt", "--output", "output.txt"});

    ProgramOptions options;
    EXPECT_EXIT(options.Parse(argc, argv), ::testing::ExitedWithCode(1),
                "Error: Invalid command specified"  // Проверяем наличие текста в выводе
    );

    free_argv(argc, argv);
}

TEST(ProgramOptions, ShortOptions) {
    auto [argc, argv] = create_argv({"program", "-c", "checksum", "-i", "short.txt", "-o", "short_out.txt"});

    ProgramOptions options;
    options.Parse(argc, argv);

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "short.txt");
    EXPECT_EQ(options.GetOutputFile(), "short_out.txt");

    free_argv(argc, argv);
}
