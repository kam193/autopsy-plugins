# This file is based on the sample from Autopsy repository

# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple file-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/latest/index.html for documentation

import jarray
import inspect
import socket
import json
try:
    from urllib2 import urlopen, Request, URLError, HTTPError
except ImportError:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
from javax.naming import Context, NamingException
from javax.naming.directory import InitialDirContext, Attribute
from java.util import Hashtable
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from java.security import MessageDigest
from java.util import Arrays

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class HashlookupFileIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Hashlookup file ingest Module"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "On each file, it makes a lookup to the CIRCL Hashlookup service to define if the file is known."

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return HashlookupFileIngestModule()


class HashlookupFileIngestModule(FileIngestModule):

    _logger = Logger.getLogger(HashlookupFileIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        self.filesFound = 0

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False) or
            (file.getSize() == 0)
            ):
            return IngestModule.ProcessResult.OK

        # TODO: check other hashes if possible
        md5 = file.getMd5Hash() or self._calculateMD5(file)
        if not md5:
            self.log(Level.WARNING, "File has no MD5 hash: " + file.getName())
            return IngestModule.ProcessResult.OK

        results = self.lookupMD5Hash(md5)
        # no information
        if not results:
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()

        self.filesFound += 1

        hashlookup_trust = results.get("hashlookup:trust", 50)
        score = Score.SCORE_UNKNOWN
        set_name = "Hashlookup:Unknown trust"
        if hashlookup_trust <= 30:
            score = Score.SCORE_NOTABLE
            set_name = "Hashlookup:Untrusted"
        elif hashlookup_trust < 50:
            score = Score.SCORE_LIKELY_NOTABLE
            set_name = "Hashlookup:Likely Untrusted"
        elif hashlookup_trust > 90:
            score = Score.SCORE_NONE
            set_name = "Hashlookup:Trusted"
        elif hashlookup_trust > 65:
            score = Score.SCORE_LIKELY_NONE
            set_name = "Hashlookup:Likely Trusted"


        comment = "Hashlookup Trust score: " + str(hashlookup_trust)
        if "FileName" in results:
            comment += ", FileName: " + results.get("FileName")
        if "source" in results:
            comment += ", Source: " + results.get("source")
        if "hashlookup:parent-total" in results:
            comment += ", Parent Total: " + str(results.get("hashlookup:parent-total"))
        if "KnownMalicious" in results:
            comment += ", KnownMalicious: " + str(results.get("KnownMalicious"))
        if "ProductCode" in results:
            comment += ", ProductCode: \n" + json.dumps(results.get("ProductCode"))
        if "parents" in results and len(results.get("parents")) > 0:
            comment += ", first Parent: \n" + json.dumps(results.get("parents")[0])

        attrs = Arrays.asList(
                BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                  HashlookupFileIngestModuleFactory.moduleName, set_name),
                BlackboardAttribute(BlackboardAttribute.Type.TSK_COMMENT,
                  HashlookupFileIngestModuleFactory.moduleName, comment)
        )

        art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_HASHSET_HIT, score,
                                        None, set_name, None, attrs).getAnalysisResult()

        try:
            blackboard.postArtifact(art, HashlookupFileIngestModuleFactory.moduleName, self.context.getJobId())
        except Blackboard.BlackboardException as e:
            self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, HashlookupFileIngestModuleFactory.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)

    def lookupMD5Hash(self, md5Hash):
        if not self._hash_exists(md5Hash):
            return None
        else:
            # Query the Hashlookup API for detailed information
            try:
                url = "https://hashlookup.circl.lu/lookup/md5/" + md5Hash.lower()
                request = Request(url)
                request.add_header('User-Agent', 'Autopsy-Hashlookup-Plugin/1.0')

                response = urlopen(request, timeout=10)
                data = response.read()

                result = json.loads(data)
                self.log(Level.INFO, "Retrieved details for hash: " + md5Hash)
                return result

            except HTTPError as e:
                self.log(Level.WARNING, "HTTP Error querying Hashlookup API: " + str(e.code))
                return None
            except URLError as e:
                self.log(Level.WARNING, "Network error querying Hashlookup API: " + str(e.reason))
                return None
            except Exception as e:
                self.log(Level.SEVERE, "Error querying Hashlookup API: " + str(e))
                return None

    def _hash_exists(self, md5Hash):
        try:
            dnsQuery = md5Hash.lower() + ".dns.hashlookup.circl.lu"

            # Use Java's JNDI API to query DNS TXT records
            env = Hashtable()
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory")

            ctx = InitialDirContext(env)
            attrs = ctx.getAttributes(dnsQuery, ["TXT"])
            txtAttr = attrs.get("TXT")

            if txtAttr is not None and txtAttr.size() > 0:
                self.log(Level.FINE, "Hash found in Hashlookup DNS: " + md5Hash)
                return True
            else:
                self.log(Level.FINE, "Hash not found in Hashlookup DNS: " + md5Hash)
                return False
        # explicitly catch java exceptions
        except NamingException as e:
            self.log(Level.FINE, "Hash not found in Cymru Malware Hash DNS: " + md5Hash + " (DNS error: " + str(e.getMessage()) + ")")
            return None
        except Exception as e:
            # DNS lookup failed - hash not found or DNS error
            self.log(Level.FINE, "Hash not found in Hashlookup DNS: " + md5Hash)
            return False

    def _calculateMD5(self, file):
        try:
            md5 = MessageDigest.getInstance("MD5")
            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(8192, "b")  # 8KB buffer
            bytesRead = inputStream.read(buffer)

            while bytesRead != -1:
                md5.update(buffer, 0, bytesRead)
                bytesRead = inputStream.read(buffer)

            inputStream.close()

            hashBytes = md5.digest()
            hexString = ""
            for b in hashBytes:
                hexString += "%02x" % (b & 0xff)

            self.log(Level.INFO, "Calculated MD5: " + hexString + " for file: " + file.getName())

            # TODO
            # file.setMd5Hash(hexString)
            return hexString

        except Exception as e:
            self.log(Level.SEVERE, "Error calculating MD5 hash: " + str(e))
            return None