#include "cmd_options.h"
#include "gtest/gtest.h"
#include <gtest/gtest.h>

using namespace CryptoGuard;
namespace po = boost::program_options;

TEST(ProgramOptions, HelpOption) {
    std::array<const char *, 2> arguments = {"program", "--help"};

    testing::internal::CaptureStdout();
    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(arguments.size(), const_cast<char **>(arguments.data())));

    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("Allowed options") != std::string::npos);
}

TEST(ProgramOptions, ValidEncryptCommand) {
    std::array<const char *, 9> arguments = {"program",  "--command",  "encrypt",    "--input", "input.txt",
                                             "--output", "output.enc", "--password", "secret"};

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(arguments.size(), const_cast<char **>(arguments.data())));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.enc");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ValidDecryptCommand) {
    std::array<const char *, 9> arguments = {"program", "-c",         "decrypt", "-i",    "input.enc",
                                             "-o",      "output.txt", "-p",      "secret"};

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(arguments.size(), const_cast<char **>(arguments.data())));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.enc");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

TEST(ProgramOptions, ValidChecksumCommand) {
    std::array<const char *, 7> arguments = {"program",  "--command", "checksum",    "--input",
                                             "data.bin", "--output",  "checksum.txt"};

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(arguments.size(), const_cast<char **>(arguments.data())));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "data.bin");
    EXPECT_EQ(options.GetOutputFile(), "checksum.txt");
}

TEST(ProgramOptions, MissingRequiredOption) {
    std::array<const char *, 5> arguments = {
        "program", "--command", "encrypt", "--input", "input.txt"
        // Нет --output и --password
    };

    ProgramOptions options;

    EXPECT_NO_THROW(
        try {
            options.Parse(arguments.size(), const_cast<char **>(arguments.data()));
            FAIL() << "При отсутствии необходимого параметра запуска должно выбрасываться исключение";
        } catch (const po::error &e) {
            std::string msg = e.what();
            EXPECT_TRUE(msg.contains("is required for")) << "Текст исключения в случае отсутствия необходимого "
                                                            "параметра запуска должен содержать с \"is required for\" ";
        })
        << "Тип исключения при отсутствии необходимого параметра запуска должен быть boost::program_options::error";
}

TEST(ProgramOptions, MissingPasswordForEncrypt) {
    std::array<const char *, 7> arguments = {
        "program",   "--command", "encrypt",   "--input",
        "input.txt", "--output",  "output.enc"
        // Нет --password
    };

    ProgramOptions options;

    EXPECT_NO_THROW(
        try {
            options.Parse(arguments.size(), const_cast<char **>(arguments.data()));
            FAIL() << "При отсутствии необходимого параметра запуска должно выбрасываться исключение";
        } catch (const po::error &e) {
            std::string msg = e.what();
            EXPECT_TRUE(msg.contains("is required for")) << "Текст исключения в случае отсутствия необходимого "
                                                            "параметра запуска должен содержать с \"is required for\" ";
        })
        << "Тип исключения при отсутствии необходимого параметра запуска должен быть boost::program_options::error";
}

TEST(ProgramOptions, InvalidCommand) {
    std::array<const char *, 7> arguments = {"program",   "--command", "invalid",   "--input",
                                             "input.txt", "--output",  "output.txt"};

    ProgramOptions options;

    EXPECT_NO_THROW(
        try {
            options.Parse(arguments.size(), const_cast<char **>(arguments.data()));
            FAIL() << "При некорректном параметре запуска (command) должно выбрасываться исключение";
        } catch (const po::error &e) {
            std::string msg = e.what();
            EXPECT_TRUE(msg.contains("Invalid command specified"))
                << "Текст исключения при некорректном параметре запуска (command) должен содержать с \"Invalid command "
                   "specified\" ";
        })
        << "Тип исключения при некорректном параметре запуска (command) должен быть boost::program_options::error";
}

TEST(ProgramOptions, ShortOptions) {
    std::array<const char *, 7> arguments = {"program", "-c", "checksum", "-i", "short.txt", "-o", "short_out.txt"};

    ProgramOptions options;

    EXPECT_NO_THROW(options.Parse(arguments.size(), const_cast<char **>(arguments.data())));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "short.txt");
    EXPECT_EQ(options.GetOutputFile(), "short_out.txt");
}
