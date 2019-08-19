using System;
using System.Security.Cryptography;
using Xunit;

namespace HyperLogLog.Tests
{
    public class ProbabilisticTests
    {
        private static readonly RandomNumberGenerator RandomNumberGenerator = RandomNumberGenerator.Create();
        private const double OnePercent = 0.01;
        private const double ZeroFivePercent = 0.005;

        [Theory]
        [InlineData(2000000)]
        [InlineData(10000000)]
        public void TheRandomTheory(int realCardinality)
        {
            const int precision = 18;

            var hll = new HyperLogLog(precision);

            for (var i = 0; i < realCardinality; i++)
            {
                var randomBytes = new byte[8];
                RandomNumberGenerator.GetBytes(randomBytes);
                var hashValue = BitConverter.ToUInt64(randomBytes, 0);
                hll.Add(hashValue);
            }

            var cardinalityEstimate = hll.Count();

            var percentageDifference = GetPercentageDifference(realCardinality, cardinalityEstimate);
            Assert.True(percentageDifference < OnePercent);
        }

        [Theory]
        [InlineData(1000000)]
        [InlineData(2000000)]
        public void TheHashedRandomTheory(int realCardinality)
        {
            const int precision = 18;

            var hll = new HyperLogLog(precision);

            using (var hashAlgorithm = new SHA1CryptoServiceProvider())
            {
                for (var i = 0; i < realCardinality; i++)
                {
                    var randomBytes = new byte[12];
                    RandomNumberGenerator.GetBytes(randomBytes);
                    var hashValue = HyperLogLog.Hash(hashAlgorithm, randomBytes);
                    hll.Add(hashValue);
                }
            }

            var cardinalityEstimate = hll.Count();

            var percentageDifference = GetPercentageDifference(realCardinality, cardinalityEstimate);
            Assert.True(percentageDifference < OnePercent);
        }

        [Theory]
        [InlineData(2000000)]
        public void HashedVsRandom(int realCardinality)
        {
            const int precision = 18;

            var hllRandom = new HyperLogLog(precision);

            for (var i = 0; i < realCardinality; i++)
            {
                var randomBytes = new byte[8];
                RandomNumberGenerator.GetBytes(randomBytes);
                var hashValue = BitConverter.ToUInt64(randomBytes, 0);
                hllRandom.Add(hashValue);
            }

            var cardinalityEstimateRandom = hllRandom.Count();

            var hllHashed = new HyperLogLog(precision);

            using (var hashAlgorithm = new SHA1CryptoServiceProvider())
            {
                for (var i = 0; i < realCardinality; i++)
                {
                    var randomBytes = new byte[12];
                    RandomNumberGenerator.GetBytes(randomBytes);
                    var hashValue = HyperLogLog.Hash(hashAlgorithm, randomBytes);
                    hllHashed.Add(hashValue);
                }
            }

            var cardinalityEstimateHashed = hllHashed.Count();

            var percentageDifference = GetPercentageDifference(cardinalityEstimateRandom, cardinalityEstimateHashed);
            Assert.True(percentageDifference < ZeroFivePercent);
        }

        private static double GetPercentageDifference(double start, double end)
        {
            var increase = end - start;
            var percentage = Math.Abs(increase) / start;

            return percentage;
        }
    }
}
