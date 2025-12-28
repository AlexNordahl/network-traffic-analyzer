#include "arguments_handler.h"

void validateArgv(int argc, const char *argv[])
{
    std::array<std::string_view, 6> validArgs {"-d", "-l", "-f", "--device", "--list", "--filter"};

    for (int i = 0; i < argc; ++i)
    {
        if (argv[i][0] == '-')
        {
            if (std::find(validArgs.begin(), validArgs.end(), argv[i]) == validArgs.end())
            {
                throw std::logic_error("unknown flag, try using -d, -l, -f, --device, --list, --filter");
            }
        }
    }
}

std::optional<std::string> selectDeviceArgument(int argc, const char* argv[])
{
    if (argc == 1)
        return std::nullopt;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0 or strcmp(argv[i], "--device") == 0)
        {
            return argv[i + 1];
        }
    }

    return std::nullopt;
}


bool listDevicesArgument(int argc, const char *argv[])
{
    if (argc == 1)
    return false;
    
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-l") == 0 or strcmp(argv[i], "--list") == 0)
        {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> filterArgument(int argc, const char* argv[])
{
    if (argc == 1)
        return std::nullopt;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-f") == 0 or strcmp(argv[i], "--filter") == 0)
        {
            return argv[i + 1];
        }
    }

    return std::nullopt;
}