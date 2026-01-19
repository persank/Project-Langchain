from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from models import ParsedLog

def parse_log(log: str, llm):
    parser = PydanticOutputParser(pydantic_object=ParsedLog)

    prompt = PromptTemplate(
        template="""
You are a SOC log parsing agent.
Extract structured security fields from this Splunk log.

Log:
{log}

{format_instructions}
""",
        input_variables=["log"],
        partial_variables={
            "format_instructions": parser.get_format_instructions()
        }
    )

    chain = prompt | llm | parser
    return chain.invoke({"log": log})


