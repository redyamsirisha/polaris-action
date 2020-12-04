const core = require('@actions/core');
const shell = require('shelljs');
const fs = require('fs');
const superagent = require('superagent');

//const polarisServerUrl = core.getInput('polarisServerUrl');
//const polarisAccessToken = core.getInput('polarisAccessToken');

const polarisServerUrl = 'https://csprod.polaris.synopsys.com'
const polarisAccessToken = 'erbsrhcmj513j678hil89j5nsesqfvventnj8o9gin0l9stmjv20'
const sarifOutputFileName = core.getInput('polaris-results-sarif');
var rcode = -1

//Polaris API
const authAPI='/api/auth/v1/authenticate'
const projectsAPI='/api/common/v0/projects'
const issuesAPI='/api/query/v1/issues'
const eventsAPI='/api/code-analysis/v0/events-with-source'

//invoke polaris scan
//shell.exec(`export POLARIS_SERVER_URL=${polarisServerUrl}`)
//shell.exec(`export POLARIS_ACCESS_TOKEN=${polarisAccessToken}`)
//shell.exec(`wget -q ${polarisServerUrl}/api/tools/polaris_cli-linux64.zip`)
//shell.exec(`unzip -j polaris_cli-linux64.zip -d /tmp`)
//shell.exec(`/tmp/polaris analyze -w`)

console.log("Fetching Polaris Results")

getIssues()

function getIssues() {
    (async () => {
        try {
            const tokenResponse = await superagent.post(polarisServerUrl+authAPI)
            .send({ accesstoken : polarisAccessToken})
            .set('Content-Type', 'application/x-www-form-urlencoded')
            let token = tokenResponse.body.jwt;
            //console.log(token);

            const projectResponse = await superagent.get(polarisServerUrl+projectsAPI)
            .query('filter[project][name][$eq]=sig-devsecops/insecure-bank')
            .query('include[project][]=branches&page[limit]=500&page[offset]=0')
            .set('Authorization', 'Bearer '+token)
            let project_id = projectResponse.body.data[0].id;
            let branch_id = projectResponse.body.included[0].id;
            console.log(project_id);
            console.log(branch_id);

            const issuesResponse = await superagent.get(polarisServerUrl+issuesAPI)
            .query('project-id='+project_id)
            .query('branch-id='+branch_id)
            .query('filter[issue][status][$eq]=opened&include[issue][]=severity&page[offset]=0&page[limit]=1000000000')
            .query('include[issue][]=issue-type&include[issue][]=path&include[issue][]=related-taxa')
            .set('Authorization', 'Bearer '+token)
            let issuesResponseData = issuesResponse.body.data.length;
            let issuesResponseIncluded = issuesResponse.body.included;
            console.log(issuesResponseData);
            console.log(issuesResponseIncluded[0].attributes);
            

        } catch (error) {
            console.log(error.response.body);
        }
    })();
}

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

