const core = require('@actions/core');
const shell = require('shelljs');
const fs = require('fs');

const polarisServerUrl = core.getInput('polarisServerUrl');
const polarisAccessToken = core.getInput('polarisAccessToken');
const sarifOutputFileName = core.getInput('polaris-results-sarif');
var rcode = -1

//invoke polaris scan
//shell.exec(`export POLARIS_SERVER_URL=${polarisServerUrl}`)
//shell.exec(`export POLARIS_ACCESS_TOKEN=${polarisAccessToken}`)
//shell.exec(`wget -q ${polarisServerUrl}/api/tools/polaris_cli-linux64.zip`)
//shell.exec(`unzip -j polaris_cli-linux64.zip -d /tmp`)
//shell.exec(`/tmp/polaris analyze -w`)

//fetch polaris scan results

//

// none,note,warning,error
const impactToLevel = (impact => {
    switch (impact) {
        case "High":
          return "error";
        case "Medium":
          return "warning";
        case "Low":
          return "note";
        default:
          return "none";
    }
})

const addRuleToRules = (issue,rules) => {
    if (rules.filter(ruleItem => ruleItem.id===issue.checkerProperties.cweCategory).length>0) {
        return null;
    }
    let rule = {
        id: issue.checkerProperties.cweCategory,
        shortDescription: {
            text: "CWE-"+issue.checkerProperties.cweCategory+": "+issue.checkerProperties.subcategoryShortDescription
        },
        helpUri: "https://cwe.mitre.org/data/definitions/"+issue.checkerProperties.cweCategory+".html",
        help: {
            text: "CWE-"+issue.checkerProperties.cweCategory+": "+issue.checkerProperties.subcategoryLongDescription
          },
        properties: {
            category: issue.checkerProperties.category
        },
        defaultConfiguration: {
            level: impactToLevel(issue.checkerProperties.impact)
        }
    }

    return rule;
}

const convertPipelineResultFileToSarifFile = (inputFileName,outputFileName) => {
    var results = {};

    let rawdata = fs.readFileSync(inputFileName);
    results = JSON.parse(rawdata);
    console.log('Pipeline Scan results file found and parsed - validated JSON file');

    let issues = results.issues;
    console.log('Issues count: '+issues.length);

    let rules=[];

    // convert to SARIF json
    let sarifResults = issues.map(issue => {
        // append rule to ruleset - if not already there
        let rule = addRuleToRules(issue,rules);
        if (rule!==null){
            rules.push(rule);
        }

        let location = {}
        let eventDescription = ""
        issue.events.map(event => {
            if (event.main==true) {
                location = {
                    physicalLocation: {
                        artifactLocation: {
                            uri: event.strippedFilePathname
                        },
                        region: {
                            startLine: parseInt(event.lineNumber)
                        }
                    }
                }
                eventDescription = eventDescription.concat(event.eventDescription)
            }
            else if (event.eventTag == "remediation") {
                eventDescription = eventDescription.concat(event.eventDescription)
            }
        })

        // get the severity according to SARIF
        let sarImp = impactToLevel(issue.checkerProperties.impact);
        // populate issue
        let resultItem = {
            level: sarImp,
            message: {
                text: eventDescription,
            },
            locations: [location],
            ruleId: issue.checkerProperties.cweCategory
        }
        return resultItem;
    })

    // construct the full SARIF content
    let sarifFileJSONContent = {
        $schema : "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version : "2.1.0",
        runs : [
            {
                tool : {
                    driver : {
                        name : "Polaris Static Analysis Results",
                        rules: rules
                    }
                },
                results: sarifResults
            }   
        ]
    };

    // save to file
    fs.writeFileSync(outputFileName,JSON.stringify(sarifFileJSONContent, null, 2));
    console.log('SARIF file created: '+outputFileName);
}

try {
    convertPipelineResultFileToSarifFile(pipelineInputFileName,sarifOutputFileName);
} catch (error) {
    core.setFailed(error.message);
}

module.exports = {
    convertToSarif: convertPipelineResultFileToSarifFile
}

