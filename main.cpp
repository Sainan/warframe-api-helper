#include <iostream>
#include <unordered_map>

#include <aes.hpp>
#include <HttpRequest.hpp>
#include <json.hpp>
#include <Pattern.hpp>
#include <Process.hpp>
#include <ProcessHandle.hpp>
#include <string.hpp>

using namespace soup;

static const uint8_t key[16] = { 76, 69, 79, 45, 65, 76, 69, 67, 9, 69, 79, 45, 65, 76, 69, 67 };
static const uint8_t iv[16] = { 49, 50, 70, 71, 66, 51, 54, 45, 76, 69, 51, 45, 113, 61, 57, 0 };

[[nodiscard]] static std::string gruzzleAuthz(const ProcessHandle& mod)
{
	std::cout << "Gruzzling";
	std::unordered_map<std::string, int> candidates{};
	const auto pattern = Pattern("3F 61 63 63 6F 75 6E 74 49 64 3D"); // ?accountId=
	for (const auto& ai : mod.getAllocations())
	{
		if (auto res = mod.externalScan(ai.range, pattern))
		{
			res = res.add(11);

			char accountId[24];
			mod.externalRead(res, accountId, 24);
			res = res.add(24);

			res = res.add(7); // &nonce=

			std::string authz = "?accountId=" + std::string(accountId, 24) + "&nonce=";
			char c;
			do
			{
				c = mod.externalRead<char>(res);
				res = res.add(1);
			} while (string::isNumberChar(c) && (authz.push_back(c), true));
			std::cout << ".";
			if (auto e = candidates.find(authz); e != candidates.end())
			{
				if (++e->second == 3)
				{
					std::cout << " The crumbs have been gruzzled." << std::endl;
					return authz;
				}
			}
			else
			{
				candidates.emplace(authz, 1);
			}
		}
	}
	std::cout << " Failed to gruzzle the crumbs." << std::endl;
	return {};
}

int main()
{
	auto proc = Process::get("Warframe.x64.exe");
	if (!proc)
	{
		std::cout << "Process not found." << std::endl;
		system("pause > nul");
		return 1;
	}
	auto mod = proc->open();
	SOUP_IF_UNLIKELY (!mod)
	{
		std::cout << "Failed to open process." << std::endl;
		system("pause > nul");
		return 2;
	}
	auto authz = gruzzleAuthz(*mod);
	SOUP_IF_UNLIKELY (authz.empty())
	{
		system("pause > nul");
		return 3;
	}
	std::cout << authz << std::endl;
	std::cout << "Downloading inventory... ";
	// Note: Could also use api.warframe.com
	HttpRequest hr("mobile.warframe.com", "/api/inventory.php" + authz);
	auto res = hr.execute();
	SOUP_IF_UNLIKELY (!res)
	{
		std::cout << "Request failed." << std::endl;
		system("pause > nul");
		return 5;
	}
	auto inventory = std::move(res->body);
	auto jr = json::decode(inventory);
	SOUP_IF_UNLIKELY (!jr)
	{
		std::cout << "Received an invalid response." << std::endl;
		system("pause > nul");
		return 6;
	}
	string::toFile("inventory.json", jr->encodePretty());
	aes::pkcs7Pad(inventory);
	aes::cbcEncrypt(
		reinterpret_cast<uint8_t*>(inventory.data()), inventory.size(),
		key, 16,
		iv
	);
	string::toFile("lastData.dat", inventory);
	std::cout << "Saved to inventory.json & lastData.dat in working directory." << std::endl;
	system("pause > nul");
	return 0;
}
