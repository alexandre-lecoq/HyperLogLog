using System;
using System.Security.Cryptography;
using Xunit;

namespace HyperLogLog.Tests
{
    public class Tests
    {
        [Fact]
        public void ConstructHyperLogLog2Throws()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new HyperLogLog(2));
        }

        [Fact]
        public void ConstructHyperLogLog4DoesNotThrow()
        {
            var hll = new HyperLogLog(7);
        }

        [Fact]
        public void ConstructHyperLogLog10DoesNotThrow()
        {
            var hll = new HyperLogLog(10);
        }

        [Fact]
        public void ConstructHyperLogLog18DoesNotThrow()
        {
            var hll = new HyperLogLog(18);
        }

        [Fact]
        public void ConstructHyperLogLog20Throws()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new HyperLogLog(20));
        }

        [Fact]
        public void Add0()
        {
            var hll = new HyperLogLog(18);
            hll.Add(0);
            var estimatedCount = hll.Count();

            Assert.Equal(189083, estimatedCount);
        }

        [Fact]
        public void Add1()
        {
            var hll = new HyperLogLog(18);
            hll.Add(1);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void Add2()
        {
            var hll = new HyperLogLog(18);
            hll.Add(2);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void Add3()
        {
            var hll = new HyperLogLog(18);
            hll.Add(3);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void Add4()
        {
            var hll = new HyperLogLog(18);
            hll.Add(4);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void Add5()
        {
            var hll = new HyperLogLog(18);
            hll.Add(5);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void Add9999999999999999999()
        {
            var hll = new HyperLogLog(18);
            hll.Add(9999999999999999999);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }

        [Fact]
        public void AddMaxULong()
        {
            var hll = new HyperLogLog(18);
            hll.Add(ulong.MaxValue);
            var estimatedCount = hll.Count();

            Assert.Equal(189084, estimatedCount);
        }
        
        [Fact]
        public void AddTwiceDoesNotChangeCount()
        {
            var hll1 = new HyperLogLog(18);
            hll1.Add(ulong.MaxValue);
            hll1.Add(ulong.MaxValue);
            var estimatedCount1 = hll1.Count();

            var hll2 = new HyperLogLog(18);
            hll2.Add(ulong.MaxValue);
            var estimatedCount2 = hll2.Count();

            Assert.Equal(estimatedCount1, estimatedCount2);
        }

        [Fact]
        public void CountWithoutAdd()
        {
            var hll = new HyperLogLog(18);
            var estimatedCount = hll.Count();

            Assert.Equal(189083, estimatedCount);
        }
        
        [Fact]
        public void HashConstantWithMD5()
        {
            const ulong value = 0x2D51AF5C52FDE6B4ul;
            
            using (var hashAlgorithm = new MD5CryptoServiceProvider())
            {
                var hashValue = HyperLogLog.Hash(hashAlgorithm, BitConverter.GetBytes(value));

                Assert.Equal(16663394367412432550ul, hashValue);
            }
        }

        [Fact]
        public void HashConstantWithSHA1()
        {
            const ulong value = 0x2D51AF5C52FDE6B4ul;

            using (var hashAlgorithm = new SHA1CryptoServiceProvider())
            {
                var hashValue = HyperLogLog.Hash(hashAlgorithm, BitConverter.GetBytes(value));

                Assert.Equal(17851087020509344997ul, hashValue);
            }
        }
    }
}
