using NorenRestApiWrapper;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NorenRestSample
{
    internal static class Base32
    {

        /// <summary>
        /// Convert a given base32 string into an array of bytes
        /// </summary>
        internal static byte[] ToByteArray(string input)
        {
            input = input.TrimEnd('=');
            int numBytes = input.Length * 5 / 8;
            byte[] result = new byte[numBytes];

            byte curByte = 0, bitsRemaining = 8;
            int mask = 0;
            int arrayIndex = 0;

            foreach (char c in input)
            {
                int ascii = CharToInt(c);

                if (bitsRemaining > 5)
                {
                    mask = ascii << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = ascii >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    result[arrayIndex++] = curByte;
                    curByte = (byte)(ascii << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            if (arrayIndex != numBytes)
            {
                result[arrayIndex] = curByte;
            }

            return result;
        }

        // Helper - convert a base32 character into an int
        private static int CharToInt(char c)
        {
            int ascii = c;

            // upper case letters
            if (ascii < 91 && ascii > 64)
            {
                return ascii - 65;
            }

            // lower case letters
            if (ascii < 123 && ascii > 96)
            {
                return ascii - 97;
            }

            // digits 2 through 7
            if (ascii < 56 && ascii > 49)
            {
                return ascii - 24;
            }

            throw new ArgumentException(string.Format("Invalid base32 character {0}", c));
        }
    }
    public sealed class Totp
    {
        private static readonly DateTime m_unixEpoch =
            new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private const int FREQUENCY_SECONDS = 30;

        private readonly string m_authenticationCode;
        private readonly DateTime m_expiry;

        public Totp(string base32Secret)
        {
            byte[] secretBytes = Base32.ToByteArray(base32Secret);

            DateTime utcNow = DateTime.UtcNow;
            long unixNow = ToUnixTime(utcNow);
            long timestamp = Convert.ToInt64(unixNow / FREQUENCY_SECONDS);
            byte[] timestampBytes = BitConverter.GetBytes(timestamp).ToArray();
            // IBM PC architecture is little endian
            Array.Reverse(timestampBytes);

            using (HMACSHA1 hmac = new HMACSHA1(secretBytes))
            {
                byte[] hmacBytes = hmac.ComputeHash(timestampBytes);
                int offset = hmacBytes.Last() & 0x0F;

                int firstByte = (hmacBytes[offset + 0] & 0x7F) << 24;
                int secondByte = hmacBytes[offset + 1] << 16;
                int thirdByte = hmacBytes[offset + 2] << 8;
                int fourthByte = hmacBytes[offset + 3];

                int authenticationCode =
                    (firstByte | secondByte | thirdByte | fourthByte) % 1000000;

                // pad with leading zeroes
                m_authenticationCode = authenticationCode.ToString().PadLeft(6, '0');
                m_expiry = GetExpiry(utcNow);
            }
        }

        /// <summary>
        /// The 6-digit authentication code itself
        /// </summary>
		public string AuthenticationCode { get { return m_authenticationCode; } }

        /// <summary>
        /// Expiration date of this authentication code in UTC time
        /// </summary>
		public DateTime ExpiryUtc { get { return m_expiry; } }

        /// <summary>
        /// True when this authentication code is expired
        /// </summary>
        public bool IsExpired
        {
            get
            {
                return DateTime.UtcNow > m_expiry;
            }
        }

        /// <summary>
        /// The length of the maximum validity period for an authentication code
        /// </summary>
        public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(FREQUENCY_SECONDS);

        public override string ToString()
        {
            string expiry = m_expiry.ToString("hh:mm:ss.fff");
            return "Authentication code: " + m_authenticationCode +
                " (expires at " + expiry + " UTC)";
        }

        // Helper - get expiration based on the generation time
        private static DateTime GetExpiry(DateTime generationTimeUtc)
        {
            long unixNow = ToUnixTime(generationTimeUtc);
            long secondsToExpiry = FREQUENCY_SECONDS - unixNow % FREQUENCY_SECONDS;
            DateTime expiry = generationTimeUtc + TimeSpan.FromSeconds(secondsToExpiry);

            if (expiry.Second % FREQUENCY_SECONDS == 0)
            {
                // mark last second of the interval as the expiry second
                expiry = expiry - TimeSpan.FromSeconds(1);
            }

            // set milliseconds to 999
            expiry = new DateTime(
                expiry.Year,
                expiry.Month,
                expiry.Day,
                expiry.Hour,
                expiry.Minute,
                expiry.Second, 999
                );
            return expiry;
        }

        // Helper - convert a date/time to a unix date stamp
        private static long ToUnixTime(DateTime dateTime)
        {
            double unixSeconds = (dateTime - m_unixEpoch).TotalSeconds;
            return Convert.ToInt64(Math.Round(unixSeconds));
        }
    }

    public static class Handlers
    {
        static NorenRestApi nApi => Program.nApi;

        public static void OnAppLoginResponse(NorenResponseMsg Response, bool ok)
        {
            //do all work here
            LoginResponse loginResp = Response as LoginResponse;

            if (loginResp.stat != "Ok")
            {
                if (loginResp.emsg == "Invalid Input : Change Password" || loginResp.emsg == "Invalid Input : Password Expired")
                {
                    //
                    Changepwd changepwd = new Changepwd();
                    changepwd.uid = Program.uid;
                    changepwd.oldpwd = Program.pwd;
                    changepwd.pwd = Program.newpwd;
                    nApi.Changepwd(Handlers.OnResponseNOP, changepwd);
                    //this will change pwd. restart to relogin with new pwd
                    return;
                }
                else if (loginResp.emsg == "Invalid Input : Blocked")
                {
                    nApi.SendForgotPassword(Handlers.OnResponseNOP, Program.endPoint, Program.uid, Program.pan, Program.dob);
                }
                return;
            }

            //we are logged in as stat is ok

            //subscribe to server for async messages            
            nApi.ConnectWatcher(Program.wsendpoint, Handlers.OnFeed, Handlers.OnOrderUpdate);
            //nApi.SubscribeOrders(Handlers.OnOrderUpdate, Program.uid);
            Program.loggedin = true;



            Program.ActionOptions();
            return;           
        }
        public static void OnUserDetailsResponse(NorenResponseMsg Response, bool ok)
        {
            UserDetailsResponse userDetailsResponse = Response as UserDetailsResponse;
            Console.WriteLine(userDetailsResponse.toJson());
        }
        public static void OnResponseNOP(NorenResponseMsg Response, bool ok)
        {
            Console.WriteLine("app handler :" + Response.toJson());
        }
        public static void OnAppLogout(NorenResponseMsg Response, bool ok)
        {
            Console.WriteLine("logout handler :" + Response.toJson());
        }

        public static void OnHoldingsResponse(NorenResponseMsg Response, bool ok)
        {
            HoldingsResponse holdingsResponse = Response as HoldingsResponse;

            Console.WriteLine("Holdings Response:" + holdingsResponse.toJson());


            printDataView(holdingsResponse.dataView);
        }

        public static void printDataView(DataView dv)
        {
            string order;
            foreach (DataRow dataRow in dv.Table.Rows)
            {
                order = "order:";
                foreach (var item in dataRow.ItemArray)
                {
                    order += item + " ,";
                }
                Console.WriteLine(order);
            }
            Console.WriteLine();
        }
        public static void OnOrderHistoryResponse(NorenResponseMsg Response, bool ok)
        {
            OrderHistoryResponse orderhistory = Response as OrderHistoryResponse;

            if (orderhistory.list != null)
            {
                DataView dv = orderhistory.dataView;

                //    for (int i = 0; i < dv.Count; i++)
                printDataView(dv);
            }
            else
            {
                Console.WriteLine("app handler: no orders");
            }
        }
        public static void OnTradeBookResponse(NorenResponseMsg Response, bool ok)
        {
            TradeBookResponse orderBook = Response as TradeBookResponse;

            if (orderBook.trades != null)
            {
                DataView dv = orderBook.dataView;

                //    for (int i = 0; i < dv.Count; i++)
                printDataView(dv);
            }
            else
            {
                Console.WriteLine("app handler: no trades");
            }
        }
        public static void OnOrderBookResponse(NorenResponseMsg Response, bool ok)
        {
            OrderBookResponse orderBook = Response as OrderBookResponse;

            if (orderBook.Orders != null)
            {
                DataView dv = orderBook.dataView;

                //    for (int i = 0; i < dv.Count; i++)
                printDataView(dv);
            }
            else
            {
                Console.WriteLine("app handler: no orders");
            }
        }
        public static void OnFeed(NorenFeed Feed)
        {
            NorenFeed feedmsg = Feed as NorenFeed;
            Console.WriteLine(Feed.toJson());
            if (feedmsg.t == "dk")
            {
                //acknowledgment
            }
            if (feedmsg.t == "df")
            {
                //feed
                Console.WriteLine($"Feed received: {Feed.toJson()}");
            }
        }
        public static void OnOrderUpdate(NorenOrderFeed Order)
        {
            Console.WriteLine($"Order update: {Order.toJson()}");
        }


    }

}
