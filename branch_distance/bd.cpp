/*
 * zproj
 *  branch distance
 * Oct 2015 Tong Zhang <ztong@vt.edu>
 */
#include "pin.H"
#include <iostream>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cassert>
#include <iomanip>

using std::stringstream;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "-o", "res.log", "specify output file name");

/*
 * log control
 */

BOOL startLog;

/*
 * log file
 */
ofstream logfile;

/*
 * Global Variables
 */

UINT64 ins_count = 0;
/*
 * Print Help Message
 */

INT32 Usage()
{
    cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */
VOID doRecBranch()
{
	if(!startLog)
	{
		return;
	}
	logfile<<ins_count<<endl;
	ins_count = 0;
}

VOID docnt()
{
	ins_count++;
}

VOID Instruction(INS ins, VOID *v)
{
	if(INS_IsBranchOrCall(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doRecBranch, IARG_END);
	}else
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docnt, IARG_END);
	}
}

VOID LogSwitchTrigger(CONTEXT * ctxt)
{
	startLog = true;
	ins_count = 0;
}

static VOID ImgLoad(IMG img, VOID * v)
{
	if (IMG_IsMainExecutable(img))
	{
		RTN mainRtn = RTN_FindByName(img, "main");
		assert(RTN_Valid(mainRtn));
		RTN_Open(mainRtn);
		RTN_InsertCall(mainRtn,
			IPOINT_BEFORE,
			AFUNPTR(LogSwitchTrigger),
			IARG_CONTEXT,
			IARG_END);
		RTN_Close(mainRtn);
	}
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	logfile<<ins_count<<endl;
	logfile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    startLog = false;
    IMG_AddInstrumentFunction(ImgLoad, 0);

    logfile.open(KnobOutputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

