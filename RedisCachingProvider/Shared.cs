using System;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Xml;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Serialization.Formatters.Binary;
using DotNetNuke.Common.Utilities;
using System.Configuration;
using DotNetNuke.Instrumentation;
using StackExchange.Redis;
using System.Runtime.InteropServices.ComTypes;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json;
using System.Text.RegularExpressions;
using System.Reflection;

namespace DotNetNuke.Providers.RedisCachingProvider
{
    internal static class Shared
    {
        internal const bool DefaultUseCompression = false;

        internal static string GetProviderConfigAttribute(string providerName, string attributeName, string defaultValue = "")
        {
            var provider = Config.GetProvider(providerName == RedisCachingProvider.ProviderName ? "caching" : "outputCaching", providerName);
            if (provider != null && provider.Attributes.AllKeys.Contains(attributeName))
                return provider.Attributes[attributeName];
            return defaultValue;
        }

        internal static string ConnectionString
        {
            get
            {
                var cs = ConfigurationManager.ConnectionStrings["RedisCachingProvider"];
                if (string.IsNullOrEmpty(cs?.ConnectionString))
                {
                    throw new ConfigurationErrorsException(
                        "The Redis connection string can't be an empty string. Check the RedisCachingProvider connectionString attribute in your web.config file.");
                }
                var connectionString = cs.ConnectionString;
                if (!connectionString.ToLowerInvariant().Contains(",abortconnect="))
                {
                    connectionString += ",abortConnect=false";
                }
                return connectionString;
            }
        }

        internal static string Serialize(object source)
        {
            // If this is binary serializable go ahead and just serialize to a Base64 string.  This can change once DNN 9.11 is out because DNN 9.11 has implemented the JsonIgnore attributes on its entities.
            if (IsSerializable(source))
                return SerializeBinary(source);
            else // If not marked as serializable then serialize as json.
                return SerializeJSON(source);
        }

        internal static T Deserialize<T>(string encodedObject)
        {
            // If this is a base64 string it must have been binary serialized
            if(IsBase64String(encodedObject))
                return DeserializeBinary<T>(encodedObject);
            else // use JSON
                return DeserializeJSON<T>(encodedObject);
        }

        /// <summary>
        /// Check to see if this object is binary serializable
        /// </summary>
        /// <param name="source">The object to check</param>
        /// <returns>True if the object has a Serializable Attribute on the class. False if it does not.</returns>
        private static bool IsSerializable(object source)
        {
            var attribute = source.GetType().GetCustomAttribute<SerializableAttribute>();
            return (attribute != null);
        }
        /// <summary>
        /// Checks if the string is base64 encoded by checking the valid characters in the string in conjunction with the length. If the string ends with = we can be more confident it is base64
        /// </summary>
        /// <param name="base64"></param>
        /// <returns>True if the string is base64</returns>
        /// <remarks>This aims to be more performant by avoiding a try catch with a conversion, since a try catch is an expensive operation.</remarks>
        public static bool IsBase64String(string base64String)
        {
            if (string.IsNullOrEmpty(base64String))
                return false;

            base64String = base64String.Trim();
            return (base64String.Length % 4 == 0) && Regex.IsMatch(base64String, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        internal static string SerializeBinary(object source)
        {
            IFormatter formatter = new BinaryFormatter();
            using (var stream = new MemoryStream())
            {
                formatter.Serialize(stream, source);
                return Convert.ToBase64String(stream.ToArray());
            }
        }

        internal static T DeserializeBinary<T>(string base64String)
        {
            using (var stream = new MemoryStream(Convert.FromBase64String(base64String)))
            {
                IFormatter formatter = new BinaryFormatter();
                stream.Position = 0;
                return (T)formatter.Deserialize(stream);
            }
        }

        internal static string SerializeJSON(object source)
        {
            if (source == null)
                throw new NullReferenceException();

            string json = JsonConvert.SerializeObject(source, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.All,
                PreserveReferencesHandling = PreserveReferencesHandling.Objects,
                NullValueHandling = NullValueHandling.Ignore
            });

            if (string.IsNullOrEmpty(json) || json == "{}")
                throw new SerializationException();

            return json;
        }

        internal static T DeserializeJSON<T>(string jsonString)
        {
            T res = JsonConvert.DeserializeObject<T>(jsonString, new JsonSerializerSettings
            {
                TypeNameHandling = TypeNameHandling.Auto,
                PreserveReferencesHandling = PreserveReferencesHandling.Objects,
                NullValueHandling = NullValueHandling.Ignore
            });
            return res;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        internal static byte[] SerializeXmlBinary(object obj)
        {
            using (var ms = new MemoryStream())
            {
                using (var wtr = XmlDictionaryWriter.CreateBinaryWriter(ms))
                {
                    var serializer = new NetDataContractSerializer();
                    serializer.WriteObject(wtr, obj);
                    ms.Flush();
                }
                return ms.ToArray();
            }
        }
        internal static object DeSerializeXmlBinary(byte[] bytes)
        {
            using (var rdr = XmlDictionaryReader.CreateBinaryReader(bytes, XmlDictionaryReaderQuotas.Max))
            {
                var serializer = new NetDataContractSerializer { AssemblyFormat = FormatterAssemblyStyle.Simple };
                return serializer.ReadObject(rdr);
            }
        }
        internal static byte[] CompressData(object obj)
        {
            byte[] inb = SerializeXmlBinary(obj);
            byte[] outb;
            using (var ostream = new MemoryStream())
            {
                using (var df = new DeflateStream(ostream, CompressionMode.Compress, true))
                {
                    df.Write(inb, 0, inb.Length);
                }
                outb = ostream.ToArray();
            }
            return outb;
        }

        internal static object DecompressData(byte[] inb)
        {
            byte[] outb;
            using (var istream = new MemoryStream(inb))
            {
                using (var ostream = new MemoryStream())
                {
                    using (var sr =
                        new DeflateStream(istream, CompressionMode.Decompress))
                    {
                        sr.CopyTo(ostream);
                    }
                    outb = ostream.ToArray();
                }
            }
            return DeSerializeXmlBinary(outb);
        }

        internal static void ClearRedisCache(IDatabase redisCache, string cacheKeyPattern)
        {
            // Run Lua script to clear cache on Redis server.
            // Lua script cannot unpack large list, so it have to unpack not over 1000 keys per a loop
            var script = "local keys = redis.call('keys', '" + cacheKeyPattern + "') " +
                         "if keys and #keys > 0 then " +
                         "for i=1,#keys,1000 do redis.call('del', unpack(keys, i, math.min(i+999, #keys))) end return #keys " +
                         "else return 0 end";
            var result = redisCache.ScriptEvaluate(script);
        }

        internal static bool ProcessException(string providerName, Exception e, string key = "", object value = null)
        {
            try
            {
                if (!bool.Parse(GetProviderConfigAttribute(providerName, "silentMode", "false")))
                    return false;

                if (e.GetType() != typeof(ConfigurationErrorsException) && value != null)
                {
                    Logger.Error(
                        string.Format("Error while trying to store in cache the key {0} (Object type: {1}): {2}", key,
                            value.GetType(), e), e);
                }
                else
                {
                    Logger.Error(e.ToString());
                }
                return true;
            }
            catch (Exception)
            {
                // If the error can't be logged, allow the caller to raise the exception or not
                // so do nothing
                return false;
            }
        }

        internal static ILog _logger;
        internal static ILog Logger => _logger ?? (_logger = LoggerSource.Instance.GetLogger(typeof(RedisCachingProvider)));


    }
}
