using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HyperLogLog
{
    /// <summary>
    /// Implements HyperLogLog
    /// </summary>
    /// <remarks>
    /// References :
    /// 1) "HyperLogLog"
    ///     Wikipedia,
    ///     2019,
    ///     https://en.wikipedia.org/wiki/HyperLogLog
    /// 2) "Flajolet–Martin algorithm"
    ///     Wikipedia,
    ///     2019,
    ///     https://en.wikipedia.org/wiki/Flajolet%E2%80%93Martin_algorithm
    /// 3) "HyperLogLog: the analysis of a near-optimal cardinality estimation algorithm",
    ///     Philippe Flajolet, Éric Fusy1and, Olivier Gandouet, Frédéric Meunier,
    ///     2007,
    ///     Discrete Mathematics and Theoretical Computer Science (DMTCS), Nancy, France
    /// 4) "HyperLogLog in Practice: Algorithmic Engineering of a State of The Art Cardinality Estimation Algorithm",
    ///     Stefan Heule, Marc Nunkesser, Alexander Hall
    ///     2013,
    ///     ACM
    /// </remarks>
    /// <remarks>
    /// Basic understanding :
    ///
    /// 1) Adding a hash value which was already added before does not changes the internal state of hyperloglog.
    ///    Therefore the current state is only affected by distinct values added to the state.
    ///
    /// 2) If we're only adding random numbers to the state, it's unlikely we will find a value with long runs of least significant bits set to 0 (eg. xxxxxxx10000).
    ///    At least if we add few random values. However, if we add a lot of those random values, we'll end finding several of that kind of values.
    ///    Therefore the length of the longest run of zeroes is indicative of the number of values we added.
    ///    This is true for one register.
    ///
    /// 3) Because 2) is only probabilistically true (we can still have bad luck), instead of using only one register,
    ///    we use several registers in parallel. By averaging the results of the different registers, we'll kill outliers for which the above statement is not true.
    ///
    /// 4) Since it only works if the added values are random. We hash our real values to make them look random before adding them to the state.
    /// </remarks>
    public class HyperLogLog
    {
        private readonly byte[] _registers;
        private readonly int _offset;
        private readonly ulong _mask;
        private readonly double _alphaMm2;

        /// <summary>
        /// Initializes a HyperLogLog sketch.
        /// </summary>
        /// <param name="precision">
        /// A value between 7 and 18 indicating the precision of the estimate. The higher the value, the higher the precision.
        /// </param>
        /// <remarks>
        /// The higher the precision, the more memory get used.
        /// At least 2^precision bytes will be allocated for computing the estimate.
        /// The memory consumption is constant no matter how many value is counted.
        /// For precision = 7 at least 128 bytes is used.
        /// For precision = 10 at least 1024 bytes (1 kB) is used.
        /// For precision = 14 at least 16384 bytes (16 kB) is used.
        /// For precision = 18 at least 262144 bytes (256 kB) is used.
        /// </remarks>
        public HyperLogLog(int precision)
        {
            if (precision < 7)
                throw new ArgumentOutOfRangeException(nameof(precision), precision, "Cannot be less than 7.");

            if (precision > 18)
                throw new ArgumentOutOfRangeException(nameof(precision), precision, "Cannot be more than 18.");

            var m = 1u << precision;
            _registers = new byte[m];
            _offset = sizeof(ulong) * 8 - precision;
            _mask = 0xFFFFFFFFFFFFFFFFul >> precision;

            // We don't need α16 := 0.673, α32 := 0.697 and α64 := 0.709,
            // since m will always be >= 128, since we do not allow precision to be 4, 5, or 6.
            var alphaM = 0.7213 / (1 + 1.079 / m);
            _alphaMm2 = alphaM * ((ulong)m * m);
        }

        /// <summary>
        /// Add a value to the sketch.
        /// </summary>
        /// <param name="hashValue">
        /// The 64 bits hash of the value to add.
        /// </param>
        public void Add(ulong hashValue)
        {
            var bucketIndex = hashValue >> _offset;
            var w = hashValue & _mask;
            var rhoW = (byte)Rho(w);

            if (rhoW > _registers[bucketIndex])
                _registers[bucketIndex] = rhoW;
        }

        /// <summary>
        /// Rho(x) denotes the number of leading zeros in the binary representation of x, plus one.
        /// </summary>
        /// <param name="x">An integer.</param>
        /// <returns>The number of leading zeros.</returns>
        /// <remarks>
        /// The definition of "leading" in the paper is a bit ambiguous.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Rho(ulong x)
        {
            if (x == 0)
                return 64;

            var i = 0;

            while ((x & 1) == 0)
            {
                x >>= 1;
                i++;
            }

            return i + 1;
        }

        /// <summary>
        /// Estimate the distinct count.
        /// </summary>
        /// <returns>The estimated distinct count.</returns>
        public long Count()
        {
            var z = 1.0 / _registers.Sum(register => 1.0 / (1 << register));
            var rawEstimate = _alphaMm2 * z;

            // Without correction, count will be way off for a small cardinality.
            // For precision = 7, counts <= 640 might be off.
            // For precision = 18, counts <= 1310720 might be off.
            // Since we support 64 bits hash value, we don't need to fix the estimate of values close to 2^32.

            return (long) rawEstimate;
        }

        /// <summary>
        /// Generate a 64 bits hash value.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm to use.</param>
        /// <param name="data">The data to hash.</param>
        /// <returns>The 64 bits hash value.</returns>
        public static ulong Hash(HashAlgorithm hashAlgorithm, byte[] data)
        {
            var result = hashAlgorithm.ComputeHash(data);
            var hash = BitConverter.ToUInt64(result, 0);

            return hash;
        }
    }
}
