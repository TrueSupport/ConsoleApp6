using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ConsoleApp6
{
    class Program
    {

        //private const string UpnAttrName = "userPrincipalName";
        //private const string MsDsPrincipalUserAttrName = "msDS-PrincipalName";
        //private const string UpnSearchFilter =
        //    "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(userPrincipalName={0}))";
        //private const string SamSearchFilter =
        //    "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(sAMAccountName={0}))";
        //private const string SamOrUpnSearchFilter =
        //    "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(|(samAccountName={0})(userPrincipalName={1})))";
        //private const string GroupUserFilter = "(&(name={0})(objectclass=group))";
        //private const string ExcludeDisabledAccountsFilter =
        //    "(&(|(name={0})(samaccountname={0}))(objectclass=user)(objectcategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2))";

                private const string UpnAttrName = "userPrincipalName";
            private const string MsDsPrincipalUserAttrName = "msDS-PrincipalName";
        private const string UpnSearchFilter =
            "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(userPrincipalName={0}))";
        private const string SamSearchFilter =
            "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(sAMAccountName={0}))";
        private const string SamOrUpnSearchFilter =
            "(&(objectCategory=person)(objectClass=user)(!sAMAccountType=805306370)(|(samAccountName={0})(userPrincipalName={1})))";
        private const string GroupUserFilter = "(&(name={0})(objectclass=group))";
        private const string ExcludeDisabledAccountsFilter =
            "(&(|(name={0})(samaccountname={0}))(objectclass=user)(objectcategory=person)(!userAccountControl:1.2.840.113556.1.4.803:=2))";

        private static User user;
        private static LdapConnection connection;

        private bool IsAuthenticated { get; set; }

        private static string db;



        static async Task Main(string[] args)
        {
            var u = "child@RS_Child.RuslanAD.local";
            var ip = "10.199.77.175";
             db = GetDomainDN(ip);
            user = LDAPAuthHelper.CreateUserFromInputData(u, AuthType.Basic);
            TryConnectInner(ip, u, "Fenofenora11");

        }

        /// <summary>Retrieves User distinguished name from LDAP server </summary>
        /// <returns>User DN </returns>
        public static string GetUserDN()
        {

            

            // Preparing to search the Domain for distinguishedName by the user's sAMAccountName or name LDAP attribute
            var request = new SearchRequest(db, string.Format(UpnSearchFilter, user.UserUpn), SearchScope.Subtree);

            request.Attributes.AddRange(new[] { "distinguishedName" });
            var directoryResponse = connection.SendRequest(request);
            var dnResponse = directoryResponse as SearchResponse;
            if (dnResponse == null)
                throw new DirectoryException(
                    $"Failed to retrieve the user's {user.Name} distinguished name from the directory. Error: " +
                    $"{(directoryResponse != null ? directoryResponse.ErrorMessage : string.Empty)}");

            Console.WriteLine("GetUserDN: Search Response item count: {0}", dnResponse.Entries.Count);

            if (dnResponse.Entries.Count == 0) throw new InvalidOperationException(
                $"Unable to retrieve the user's ({user.Name}) distinguished name.");

            var userDistinguishedName = dnResponse.Entries[0].DistinguishedName;

            Console.WriteLine("User's ({0}) distinguished name is {1}.", user.Name, userDistinguishedName);
            return userDistinguishedName;
        }

        private static IEnumerable<UserLogins> GetUserLogins()
        {
            // Preparing to search the Domain for the user's SAM or UPN
            var request = new SearchRequest(db,
                string.Format(SamOrUpnSearchFilter, user.Name, $"{user.Name}@{user.Domain}"), SearchScope.Subtree);
            request.Attributes.Add(MsDsPrincipalUserAttrName);
            request.Attributes.Add(UpnAttrName);
            

            var directoryResponse = connection.SendRequest(request);
            var dnResponse = directoryResponse as SearchResponse;
            if (dnResponse == null)
                throw new DirectoryException(
                    $"Failed to retrieve the user's {user.Name} attributes from the directory. " +
                    $"Error: {((directoryResponse != null) ? directoryResponse.ErrorMessage : string.Empty)}");

            Console.WriteLine("GetUserAttributes: Search response item count: {0}", dnResponse.Entries.Count);

            var result = new List<UserLogins>();

            if (dnResponse.Entries.Count <= 0)
                return result;

            foreach (SearchResultEntry entry in dnResponse.Entries)
            {
                var sam = LDAPAuthHelper.GetAttributeNameAndValue(entry.Attributes[MsDsPrincipalUserAttrName]);
                var upn = LDAPAuthHelper.GetAttributeNameAndValue(entry.Attributes[UpnAttrName]);
                result.Add(new UserLogins(sam.Value, upn.Value));
                Console.WriteLine($"GetLoginAttributes: Retrieved user's logins: {sam.Key} = {sam.Value}, {upn.Key} = {upn.Value}");
            }

            return result;
        }

        public static string GetDomainDN(string ldapServerName)
        {
            var defaultDN = string.Empty;
            SearchRequest searchRequest = new SearchRequest(null, "(objectClass=*)", SearchScope.Base);
            searchRequest.Attributes.AddRange(new[] { "defaultNamingContext" });
            using (var ldapConnection = new LdapConnection(new LdapDirectoryIdentifier(ldapServerName)))
            {
                ldapConnection.AuthType = AuthType.Anonymous;
                ldapConnection.Bind();

                

                var directoryResponse = ldapConnection.SendRequest(searchRequest);


                var response = directoryResponse as SearchResponse;
                if (response == null)
                    throw new DirectoryException(
                        $"Failed to retrieve the distinguished name from the directory. Error: " +
                        $"{(directoryResponse != null ? directoryResponse.ErrorMessage : string.Empty)}");

                Console.WriteLine("GetServerDN: Search Response item count: {0}", response.Entries.Count);

                if (response.Entries.Count == 0) throw new InvalidOperationException(
                   string.Format("Unable to retrieve the server distinguished name."));

                defaultDN = response.Entries[0].Attributes["defaultNamingContext"][0].ToString();
            }
            return defaultDN;
        }

        private static bool TryConnectInner(string server, string userName, string password, bool isThrowException = false)
        {
            user = LDAPAuthHelper.CreateUserFromInputData(userName, AuthType.Basic);
            var authType = AuthType.Basic;
            var networkCredential = LDAPAuthHelper.CreateNetworkCredential(user, userName, password, authType);
            try
            {
                Console.WriteLine($"Creating LDAP connection to '{server}'.");
                connection = new LdapConnection(server)
                {
                    AuthType = authType,
                    AutoBind = true,
                    Credential = networkCredential
                };

                connection.SessionOptions.ProtocolVersion = 3;

              var domain = LDAPAuthHelper.GetDomainNameFromDistinguishedName(db);

                // Since UPN allows to define various suffixes and combination of UPN with Kerberos requires 
                // exact domain name in the provided credential we have to create correct domain name
                // from configured domain distinguished name in this case, also we can use full non-parsed username
                if (authType == AuthType.Kerberos && user.LoginType == LoginType.Upn)
                {
                    networkCredential.Domain = domain;
                    networkCredential.UserName = userName;
                }

                // We have to do additional check for the user name
                // because of the following LDAP bind bug https://stackoverflow.com/questions/1153703/ldap-bind-s-returning-ldap-success-with-wrong-credentials
                connection.Bind(networkCredential);

                Console.WriteLine($"The user account '{userName}' was successfully connected to LDAP server '{server}' using '{authType}' authentication type.");

                // Get full SAM and UPN user names from LDAP and verify the value is equal to the login
                // provided by user in login page or LDAP test connection form
                var logins = GetUserLogins();

                var login = logins.FirstOrDefault(x =>
                    (user.LoginType == LoginType.Sam ? x.Sam : x.Upn).Equals(userName,
                        StringComparison.InvariantCultureIgnoreCase));

                if (login == null && user.LoginType == LoginType.Upn)
                {
                    // maybe we have short hand login like ldap@automation
                    // that we can convert to ldap@automation.local 
                    var userWitouhtDomain = user.Name;
                    var userWithDomain = userWitouhtDomain + "@" + domain;
                    login = logins.FirstOrDefault(x => x.Upn.Equals(userWithDomain, StringComparison.InvariantCultureIgnoreCase));
                }

                if (login != null)
                {
                    user.UserUpn = login.Upn;
                    user.UserDn = GetUserDN();
                    Console.WriteLine($"The user account '{userName}' was successfully verified using LDAP attributes.");
                    return true;
                }

                Console.WriteLine($"The user account '{userName}' was not verified using LDAP attributes.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            return false;
        }
    }



    public class LDAPAuthHelper
    {
        private const string LDAP_AuthEnabledKey = "LDAP_AuthEnabled";
        private const string LDAP_HostKey = "LDAP_Host";
        private const string LDAP_PortKey = "LDAP_Port";
        private const string LDAP_DomainDNKey = "LDAP_DomainDN";
        private const string LDAP_AuthTypeKey = "LDAP_AuthType";
        private const string LDAP_UseSSLKey = "LDAP_UseSSL";

      

        
        public static KeyValuePair<string, string> GetAttributeNameAndValue(DirectoryAttribute attribute)
        {
            if (attribute == null)
                throw new ArgumentNullException(nameof(attribute));

            return new KeyValuePair<string, string>(attribute.Name, attribute.GetValues(typeof(String))[0].ToString());
        }

        public static User CreateUserFromInputData(string userName, AuthType authType)
        {
            if (userName == null)
                throw new ArgumentNullException(nameof(userName));

            //username must be in domain\username or username@domain format
            if (userName.Trim().EndsWith("\\") || userName.Trim().EndsWith("@"))
                throw new FormatException("wrong format");

            var user = new User();

            if (userName.Contains("\\"))
            {
                var loc = userName.IndexOf('\\');
                user.Name = userName.Substring(loc + 1);
                user.Domain = userName.Substring(0, loc);
                user.LoginType = LoginType.Sam;
            }
            else if (userName.Contains("@"))
            {
                var loc = userName.IndexOf('@');
                user.Name = userName.Substring(0, loc);
                user.Domain = userName.Substring(loc + 1);
                user.LoginType = LoginType.Upn;

                //NTLM doesn't support UPN format
                if (authType == AuthType.Ntlm)
                {
                    throw new InvalidOperationException("NTLM doesn't support UPN format");
                }
            }
            else
            {
                //user name must be in either SAM or UPN format
                throw new Exception("user name must be in either SAM or UPN format");
            }
            return user;
        }

        public static NetworkCredential CreateNetworkCredential(User user, string username, string password, AuthType authType)
        {
            if (user?.Name == null || user.Domain == null)
                throw new ArgumentNullException(nameof(user));
            if (password == null)
                throw new ArgumentNullException(nameof(password));


            switch (authType)
            {
                case AuthType.Basic:
                    return new NetworkCredential(username, password, string.Empty);
                case AuthType.Ntlm:
                case AuthType.Kerberos:
                case AuthType.Negotiate:
                    return new NetworkCredential(user.Name, password, user.Domain);
                case AuthType.Anonymous:
                    return new NetworkCredential();
                default:
                    throw new NotSupportedException($"Ldap is not supported for '{authType}' type.");
            }
        }

        public static string GetDomainNameFromDistinguishedName(string distinguishedName)
        {
            if (String.IsNullOrWhiteSpace(distinguishedName))
                throw new ArgumentException(nameof(distinguishedName));

            var domainNameParts = new List<string>();
            var dnParts = distinguishedName.Trim().Split(',');

            foreach (var dnPart in dnParts)
            {
                var splittedDnPart = dnPart.Split('=');
                var dnPartName = splittedDnPart[0].Trim();
                if (dnPartName.Equals("dc", StringComparison.InvariantCultureIgnoreCase)
                    && splittedDnPart.Length > 1)
                {
                    domainNameParts.Add(splittedDnPart[1].Trim());
                }
            }

            return String.Join(".", domainNameParts);
        }
    }

    public enum LoginType { Sam, Upn }

    /// <summary>
    /// Class representing LDAP user
    /// </summary>
    public class User
    {
        public string Name { get; set; }

        public string Domain { get; set; }

        public LoginType LoginType { get; set; }

        public string UserDn { get; set; }

        public string UserUpn { get; set; }
    }

    public class UserLogins
    {
        /// <summary>
        /// Security Account Manager Format like: domain\username
        /// </summary>
        public string Sam { get; }

        /// <summary>
        /// User Principal Name - username@domain
        /// </summary>
        public string Upn { get; }

        public UserLogins(string sam, string upn)
        {
            Sam = sam;
            Upn = upn;
        }
    }





}
