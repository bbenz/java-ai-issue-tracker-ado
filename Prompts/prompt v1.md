Greetings!  Please help me create a prompt that will create a new tool.
Please only create a prompt for now, I will review it an genrate the code after iterations.  
Please ask clarifying questions

# Tool Description

The new tool will:

-Review work items in an Azure Azure DevOps (ADO) project that contain issues in the work item description
-Check the Java Project to see if the issue in each work item description still exists and produce a markdown document (details below)
-Updates to ADO will take place after human review in a markdown document.
-When an ADO item is updated, document the reason in the work item discussion and mark the issue as resolved
-NOTE: most of the issues in the work items are resolved by dependency updates.  Flag an isue if it not related to a dependency update.


# Tool operation 

We can use wharever programming language/CLI cobination will best get the job done.  

The tool will work in two steps:

1) Analysis - the tool creates an easy-to-read markdown document that lists work items, their resolution, and whether or not the work item will be marked as resolved.  The markdown document should be grouped by priority and then grouped by unresolved, then resolved for each priority grouping.  The markdown document will be reviewed before moving on to the next step - live mode.  

2) Live Mode - Mark ADO work items as resolved based on the report, after the report is reviewed, with the option to cancel without updates.  

# Working with ADO: 
-ADO Authentication should ideally be via Entra IDs, but we can also use a personal access token if Entra is not an option.  
-Please verify which of these opions is easiest to use to read ADO work items and update work items as resolved.
    -ADO SDK for Python: https://github.com/microsoft/azure-devops-python-api  
    -Azure DevOps CLI/MCP Server: https://learn.microsoft.com/en-us/azure/devops/cli/?view=azure-devops 
    -Azure DevOps MCP Server: https://github.com/microsoft/azure-devops-mcp and https://learn.microsoft.com/en-us/azure/devops/mcp-server/mcp-server-overview?view=azure-devops


# Working with AI Projects:

-The tool should review the latest stable release for the following AI projects - 
Langchain4j - version 1.12.2 - https://github.com/langchain4j/langchain4j
Spring AI - version 1.1.4 - https://github.com/spring-projects/spring-ai




