using System.Threading.Tasks;
using Fail2Ban4Win.Entry;
using Tests.Logging;
using Xunit;
using Xunit.Abstractions;

#nullable enable

namespace Tests.Entry {

    public class MainClassTest {

        public MainClassTest(ITestOutputHelper testOutputHelper) {
            XunitTestOutputTarget.start(testOutputHelper);
        }

        [Fact]
        public async Task start() {
            Task main = Task.Run(() => MainClass.Main(new string[0]));

            await Task.Delay(200);

            MainClass.stop();

            await main;
        }

    }

}