namespace NetTools
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Net;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Represents a range of IP addresses.
    /// </summary>
    /// <see cref="https://github.com/jsakamoto/ipaddressrange" />
    public class IPAddressRange : IEnumerable<IPAddress>, IDictionary<string, string>
    {
        #region "Properties"

        // Pattern 1. CIDR range: "192.168.0.0/24", "fe80::%lo0/10"
        private static Regex m1_regex = new Regex(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*/[ \t]*(?<maskLen>\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 2. Uni address: "127.0.0.1", "::1%eth0"
        private static Regex m2_regex = new Regex(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 3. Begin end range: "169.258.0.0-169.258.0.255", "fe80::1%23-fe80::ff%23"
        //            also shortcut notation: "192.168.1.1-7" (IPv4 only)
        private static Regex m3_regex = new Regex(@"^(?<begin>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*[\-–][ \t]*(?<end>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Pattern 4. Bit mask range: "192.168.0.0/255.255.255.0"
        private static Regex m4_regex = new Regex(@"^(?<adr>([\d.]+)|([\da-f:]+(:[\d.]+)?(%\w+)?))[ \t]*/[ \t]*(?<bitmask>[\da-f\.:]+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public IPAddress Begin { get; set; }
        public IPAddress End { get; set; }

        #endregion

        #region "Constructors"

        /// <summary>
        /// Creates an empty range object, equivalent to "0.0.0.0/0".
        /// </summary>
        public IPAddressRange() : this(new IPAddress(0L)) 
        { 
        }

        /// <summary>
        /// Creates a new range with the same start/end address (range of one).
        /// </summary>
        /// <param name="singleAddress"></param>
        public IPAddressRange(IPAddress singleAddress)
        {
            if (singleAddress == null)
            {
                throw new ArgumentNullException("singleAddress");
            }
            Begin = End = singleAddress;
        }

        /// <summary>
        /// Create a new range from a begin and end address.
        /// Throws an exception if Begin comes after End, or the
        /// addresses are not in the same family.
        /// </summary>
        public IPAddressRange(IPAddress begin, IPAddress end)
        {
            if (begin == null)
            {
                throw new ArgumentNullException("begin");
            }
            if (end == null)
            {
                throw new ArgumentNullException("end");
            }
            Begin = new IPAddress(begin.GetAddressBytes());
            End = new IPAddress(end.GetAddressBytes());
            if (Begin.AddressFamily != End.AddressFamily)
            {
                throw new ArgumentException("Elements must be of the same address family", "end");
            }
            var beginBytes = Begin.GetAddressBytes();
            var endBytes = End.GetAddressBytes();
            if (!BitsUtil.GtECore(endBytes, beginBytes))
            {
                throw new ArgumentException("Begin must be smaller than the End", "begin");
            }
        }

        /// <summary>
        /// Creates a range from a base address and mask bits.
        /// This can also be used with <see cref="SubnetMaskLength"/> to create a
        /// range based on a subnet mask.
        /// </summary>
        /// <param name="baseAddress"></param>
        /// <param name="maskLength"></param>
        public IPAddressRange(IPAddress baseAddress, int maskLength)
        {
            if (baseAddress == null)
            {
                throw new ArgumentNullException("baseAddress");
            }
            var baseAdrBytes = baseAddress.GetAddressBytes();
            if (baseAdrBytes.Length * 8 < maskLength)
            {
                throw new FormatException();
            }
            var maskBytes = BitsUtil.GetBitMask(baseAdrBytes.Length, maskLength);
            baseAdrBytes = BitsUtil.And(baseAdrBytes, maskBytes);
            Begin = new IPAddress(baseAdrBytes);
            End = new IPAddress(BitsUtil.Or(baseAdrBytes, BitsUtil.Not(maskBytes)));
        }

        [EditorBrowsable(EditorBrowsableState.Never), Obsolete("Use IPAddressRange.Parse static method instead.")]
        public IPAddressRange(string ipRangeString)
        {
            var parsed = Parse(ipRangeString);
            Begin = parsed.Begin;
            End = parsed.End;
        }

        #endregion

        #region "Methods"

        public bool Contains(IPAddress ipaddress)
        {
            if (ipaddress == null)
            {
                throw new ArgumentNullException("ipaddress");
            }
            if (ipaddress.AddressFamily != this.Begin.AddressFamily)
            {
                return false;
            }
            var offset = 0;
            if (Begin.IsIPv4MappedToIPv6 && ipaddress.IsIPv4MappedToIPv6)
            {
                offset = 12; //ipv4 has prefix of 10 zero bytes and two 255 bytes. 
            }
            var adrBytes = ipaddress.GetAddressBytes();
            return
                BitsUtil.LtECore(this.Begin.GetAddressBytes(), adrBytes, offset) &&
                BitsUtil.GtECore(this.End.GetAddressBytes(), adrBytes, offset);
        }

        public bool Contains(IPAddressRange range)
        {
            if (range == null)
            {
                throw new ArgumentNullException("range");
            }
            if (this.Begin.AddressFamily != range.Begin.AddressFamily)
            {
                return false;
            }
            var offset = 0;
            if (Begin.IsIPv4MappedToIPv6 && range.Begin.IsIPv4MappedToIPv6)
            {
                offset = 12; //ipv4 has prefix of 10 zero bytes and two 255 bytes. 
            }
            return
                BitsUtil.LtECore(this.Begin.GetAddressBytes(), range.Begin.GetAddressBytes(), offset) &&
                BitsUtil.GtECore(this.End.GetAddressBytes(), range.End.GetAddressBytes(), offset);
        }

        private static string StripScopeIP(string ipAddr)
        {
            return ipAddr.Split('%')[0];
        }

        public static IPAddressRange Parse(string ipRangeString)
        {
            if (ipRangeString == null)
            {
                throw new ArgumentNullException("ipRangeString");
            }
            // trim white spaces.
            ipRangeString = ipRangeString.Trim();

            // Pattern 1. CIDR range: "192.168.0.0/24", "fe80::/10%eth0"
            var m1 = m1_regex.Match(ipRangeString);
            if (m1.Success)
            {
                var baseAdrBytes = IPAddress.Parse(StripScopeIP(m1.Groups["adr"].Value)).GetAddressBytes();
                var maskLen = int.Parse(m1.Groups["maskLen"].Value);
                if (baseAdrBytes.Length * 8 < maskLen) throw new FormatException();
                var maskBytes = BitsUtil.GetBitMask(baseAdrBytes.Length, maskLen);
                baseAdrBytes = BitsUtil.And(baseAdrBytes, maskBytes);
                return new IPAddressRange(new IPAddress(baseAdrBytes), new IPAddress(BitsUtil.Or(baseAdrBytes, BitsUtil.Not(maskBytes))));
            }

            // Pattern 2. Uni address: "127.0.0.1", ":;1"
            var m2 = m2_regex.Match(ipRangeString);
            if (m2.Success)
            {
                return new IPAddressRange(IPAddress.Parse(StripScopeIP(ipRangeString)));
            }

            // Pattern 3. Begin end range: "169.258.0.0-169.258.0.255"
            var m3 = m3_regex.Match(ipRangeString);
            if (m3.Success)
            {
                // if the left part contains dot, but the right one does not, we treat it as a shortuct notation
                // and simply copy the part before last dot from the left part as the prefix to the right one
                var begin = m3.Groups["begin"].Value;
                var end = m3.Groups["end"].Value;
                if (begin.Contains('.') && !end.Contains('.'))
                {
                    if (end.Contains('%')) throw new FormatException("The end of IPv4 range shortcut notation contains scope id.");
                    var lastDotAt = begin.LastIndexOf('.');
                    end = begin.Substring(0, lastDotAt + 1) + end;
                }

                return new IPAddressRange(
                    begin: IPAddress.Parse(StripScopeIP(begin)),
                    end: IPAddress.Parse(StripScopeIP(end)));
            }

            // Pattern 4. Bit mask range: "192.168.0.0/255.255.255.0"
            var m4 = m4_regex.Match(ipRangeString);
            if (m4.Success)
            {
                var baseAdrBytes = IPAddress.Parse(StripScopeIP(m4.Groups["adr"].Value)).GetAddressBytes();
                var maskBytes = IPAddress.Parse(m4.Groups["bitmask"].Value).GetAddressBytes();
                baseAdrBytes = BitsUtil.And(baseAdrBytes, maskBytes);
                return new IPAddressRange(new IPAddress(baseAdrBytes), new IPAddress(BitsUtil.Or(baseAdrBytes, BitsUtil.Not(maskBytes))));
            }
            throw new FormatException("Unknown IP range string.");
        }

        public static bool TryParse(string ipRangeString, out IPAddressRange ipRange)
        {
            try
            {
                ipRange = IPAddressRange.Parse(ipRangeString);
                return true;
            }
            catch (Exception)
            {
                ipRange = null;
                return false;
            }
        }

        /// <summary>
        /// Takes a subnetmask (eg, "255.255.254.0") and returns the CIDR bit length of that
        /// address. Throws an exception if the passed address is not valid as a subnet mask.
        /// </summary>
        /// <param name="subnetMask">The subnet mask to use.</param>
        /// <returns></returns>
        public static int SubnetMaskLength(IPAddress subnetMask)
        {
            if (subnetMask == null)
            {
                throw new ArgumentNullException("subnetMask");
            }
            var length = BitsUtil.GetBitMaskLength(subnetMask.GetAddressBytes());
            if (length == null)
            {
                throw new ArgumentException("Not a valid subnet mask", "subnetMask");
            }
            return length.Value;
        }

        public IEnumerator<IPAddress> GetEnumerator()
        {
            var first = Begin.GetAddressBytes();
            var last = End.GetAddressBytes();
            for (var ip = first; BitsUtil.LtECore(ip, last); ip = BitsUtil.Increment(ip))
            {
                yield return new IPAddress(ip);
            }
        }

        /// <summary>
        /// Returns the range in the format "begin-end", or 
        /// as a single address if End is the same as Begin.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Equals(Begin, End) ? Begin.ToString() : string.Format("{0}-{1}", Begin, End);
        }

        public int GetPrefixLength()
        {
            byte[] byteBegin = Begin.GetAddressBytes();
            byte[] byteEnd = End.GetAddressBytes();

            // Handle single IP
            if (Begin.Equals(End))
            {
                return byteBegin.Length * 8;
            }
            int length = (byteBegin.Length * 8);
            for (int i = 0; i < length; i++)
            {
                byte[] mask = BitsUtil.GetBitMask(byteBegin.Length, i);
                if (new IPAddress(BitsUtil.And(byteBegin, mask)).Equals(Begin))
                {
                    if (new IPAddress(BitsUtil.Or(byteBegin, BitsUtil.Not(mask))).Equals(End))
                    {
                        return i;
                    }
                }
            }
            throw new FormatException(String.Format("{0} is not a CIDR Subnet", ToString()));
        }

        /// <summary>
        /// Returns a Cidr String if this matches exactly a Cidr subnet.
        /// </summary>
        public string ToCidrString()
        {
            return string.Format("{0}/{1}", Begin, GetPrefixLength());
        }  

        /// <summary>
        /// Returns the input typed as IEnumerable&lt;IPAddress&gt;.
        /// </summary>
        public IEnumerable<IPAddress> AsEnumerable()
        {
            return (this as IEnumerable<IPAddress>);
        }

        private IEnumerable<KeyValuePair<string, string>> GetDictionaryItems()
        {
            return new[] {
                new KeyValuePair<string, string>("Begin", Begin.ToString()),
                new KeyValuePair<string, string>("End", End.ToString()),
            };
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private bool TryGetValue(string key, out string value)
        {
            return TryGetValue(GetDictionaryItems(), key, out value);
        }

        private bool TryGetValue(IEnumerable<KeyValuePair<string, string>> items, string key, out string value)
        {
            items = (items ?? GetDictionaryItems());
            var foundItem = items.FirstOrDefault(item => item.Key == key);
            value = foundItem.Value;
            return foundItem.Key != null;
        }

        public void Add(string key, string value)
        {
            throw new NotImplementedException();
        }

        public bool ContainsKey(string key)
        {
            return GetDictionaryItems().Any(i => i.Key == key);
        }

        public ICollection<string> Keys
        {
            get { throw new NotImplementedException(); }
        }

        public bool Remove(string key)
        {
            throw new NotImplementedException();
        }

        bool IDictionary<string, string>.TryGetValue(string key, out string value)
        {
            throw new NotImplementedException();
        }

        public void Add(KeyValuePair<string, string> item)
        {
            throw new NotImplementedException();
        }

        public void Clear()
        {
            throw new NotImplementedException();
        }

        public bool Contains(KeyValuePair<string, string> item)
        {
            return GetDictionaryItems().Contains(item);
        }

        public void CopyTo(KeyValuePair<string, string>[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(KeyValuePair<string, string> item)
        {
            throw new NotImplementedException();
        }

        IEnumerator<KeyValuePair<string, string>> IEnumerable<KeyValuePair<string, string>>.GetEnumerator()
        {
            return GetDictionaryItems().GetEnumerator();
        }

        #endregion

        public ICollection<string> Values
        {
            get { throw new NotImplementedException(); }
        }

        public string this[string key]
        {
            get
            {
                string value;
                if (TryGetValue(key, out value))
                {
                    return value;
                }
                return String.Empty;
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public int Count
        {
            get 
            { 
                return GetDictionaryItems().Count();
            }
        }

        public bool IsReadOnly
        {
            get { return false; }
        }
    }
}