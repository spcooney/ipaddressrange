namespace NetTools
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System.Net;
    using System.Net.Sockets;

    [TestClass]
    public class IPAddressRangeTest
    {
        [TestMethod]
        public void SingleCtorTest()
        {
            string ip = "192.168.0.88";
            IPAddressRange range = new IPAddressRange(IPAddress.Parse(ip));
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals(ip));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals(ip));
        }

        [TestMethod]
        public void CtorMaskLengthTest()
        {
            string ip = "192.168.0.88";
            IPAddressRange range = new IPAddressRange(IPAddress.Parse(ip), 24);
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals("192.168.0.0"));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals("192.168.0.255"));
        }

        [TestMethod]
        public void ParseUniaddressIPv4Test()
        {
            var range = IPAddressRange.Parse("192.168.60.13");
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals("192.168.60.13"));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals("192.168.60.13"));
        }

        [TestMethod]
        public void ParseIPv4CIDRTest()
        {
            var range = IPAddressRange.Parse("219.165.64.0/19");
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals("219.165.64.0"));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals("219.165.95.255"));
        }

        [TestMethod]
        public void ParseIPv4CIDRMaxTest()
        {
            var range = IPAddressRange.Parse("219.165.64.73/32");
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals("219.165.64.73"));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals("219.165.64.73"));
        }

        [TestMethod]
        public void ParseIPv4BeginToEndTest()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            Assert.IsTrue(range.Begin.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.Begin.ToString().Equals("192.168.60.26"));
            Assert.IsTrue(range.End.AddressFamily == AddressFamily.InterNetwork);
            Assert.IsTrue(range.End.ToString().Equals("192.168.60.37"));
        }

        [TestMethod]
        public void ContainsIPv4Test()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            Assert.IsFalse(range.Contains(IPAddress.Parse("192.168.60.25")));
            Assert.IsTrue(range.Contains(IPAddress.Parse("192.168.60.26")));
            Assert.IsTrue(range.Contains(IPAddress.Parse("192.168.60.27")));
            Assert.IsTrue(range.Contains(IPAddress.Parse("192.168.60.36")));
            Assert.IsTrue(range.Contains(IPAddress.Parse("192.168.60.37")));
            Assert.IsFalse(range.Contains(IPAddress.Parse("192.168.60.38")));
        }

        [TestMethod]
        public void CountIPv4Test()
        {
            var range = IPAddressRange.Parse("192.168.60.26-192.168.60.37");
            int ranges = range.Count;
            Assert.IsTrue(ranges > 0);
        }
    }
}