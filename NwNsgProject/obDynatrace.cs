using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Formatting;

namespace nsgFunc
{
    public partial class Util
    {
        public static async Task<int> obDynatrace(string newClientContent, ILogger log)
        {
            //
            // newClientContent looks like this:
            //
            // {
            //   "records":[
            //     {...},
            //     {...}
            //     ...
            //   ]
            // }
            //

            string dynatraceUrl = Util.GetEnvironmentVariable("dynatraceUrl");
            string dynatraceApiToken = Util.GetEnvironmentVariable("dynatraceApiToken");

            if (dynatraceUrl.Length == 0 || dynatraceApiToken.Length == 0)
            {
                log.LogError("Values for dynatraceUrl and dynatraceApiToken are required.");
                return 0;
            }

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(ValidateDtCert);

            int bytesSent = 0;

            foreach (var transmission in convertToDynatraceList(newClientContent, log))
            {
                var client = new SingleHttpClientInstance();
                try
                {
                    HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, dynatraceUrl);
                    req.Headers.Accept.Clear();
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    req.Headers.Add("Authorization", "Api-Token " + dynatraceApiToken);
                    req.Content = new StringContent(transmission, Encoding.UTF8, "application/json");
                    HttpResponseMessage response = await SingleHttpClientInstance.SendToDynatrace(req);
                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        throw new System.Net.Http.HttpRequestException($"StatusCode from Dynatrace: {response.StatusCode}, and reason: {response.ReasonPhrase}");
                    }
                }
                catch (System.Net.Http.HttpRequestException e)
                {
                    throw new System.Net.Http.HttpRequestException("Sending to Dynatrace. Is Dynatrace service running?", e);
                }
                catch (Exception f)
                {
                    throw new System.Exception("Sending to Dynatrace. Unplanned exception.", f);
                }
                bytesSent += transmission.Length;
            }
            return bytesSent;
        }

        static System.Collections.Generic.IEnumerable<string> convertToDynatraceList(string newClientContent, ILogger log)
        {
            foreach (var messageList in denormalizedDynatraceEvents(newClientContent, null, log))
            {

                StringBuilder outgoingJson = StringBuilderPool.Allocate();
                outgoingJson.Capacity = MAXTRANSMISSIONSIZE;

                try
                {
                    foreach (var message in messageList)
                    {
                        var messageAsString = JsonConvert.SerializeObject(message, new JsonSerializerSettings
                        {
                            NullValueHandling = NullValueHandling.Ignore
                        });
                        outgoingJson.Append(messageAsString);
                    }
                    yield return outgoingJson.ToString();
                }
                finally
                {
                    StringBuilderPool.Free(outgoingJson);
                }

            }
        }

        public static bool ValidateDtCert(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErr)
        {
            var dynatraceCertThumbprint = Util.GetEnvironmentVariable("dynatraceCertThumbprint");

            // if user has not configured a cert, anything goes
            if (dynatraceCertThumbprint == "")
                return true;

            // if user has configured a cert, must match
            var thumbprint = cert.GetCertHashString();
            if (thumbprint == dynatraceCertThumbprint)
                return true;

            return false;
        }
    }
}
