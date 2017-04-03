/*
 * zproj
 *  Guide program execution using given branch information
 *  tested on pin-2.4-71313
 *            pin-3.0-76991
 *
 * 2016 Tong Zhang <ztong@vt.edu>
 * Spet-Dec 2015 Tong Zhang <ztong@vt.edu>
 */
#include "pin.H"

//debug level 6 generates basic memory rw info
#define _DEBUG_ 6
//#define _DEBUG_ 0

/*
 * no memory manager
 */
#define _USE_MMM_ 0

#include <iostream>
#include <fstream>
#include <sstream>
#include <cassert>
#include <cstdlib>
#include <iomanip>
#include <cstring>
#include <list>
#include <algorithm>
#include <map>

#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>

/*
 * 2.14-71313 need this definition
 * 3.0-76991 don't need this
 */
#if 0
#define SIGILL (4)
#define SIGSEGV (11)
#endif

extern "C" void (*signal(int, void (*)(int)))(int);
#if 0
/*
 * handle signal raised by pin tool
 */
void sig_die(int signum);
#endif

using std::stringstream;

KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
		"-i", "st.in", "specify input file name");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"-o", "res.log", "specify output file name");

KNOB<string> KnobDylibmmapFile(KNOB_MODE_WRITEONCE, "pintool",
		"-dylibmap", "dylib.map", "specify shared library memory map file.");

KNOB<BOOL> KnobJmpAt(KNOB_MODE_WRITEONCE, "pintool",
		"-j", "0", "jump and execute from address at the beginning of main()");

KNOB<int> KnobDrop(KNOB_MODE_WRITEONCE, "pintool",
		"-r", "0", "drop percent recover point, default is 0, drop nothing");

KNOB<BOOL> KnobPrintStraightLineCode(KNOB_MODE_WRITEONCE, "pintool",
		"-S", "0", "print executed straight line code");

KNOB<BOOL> KnobPrintRecoveredMemAccesses(KNOB_MODE_WRITEONCE, "pintool",
		"-m", "1", "print recovered memory accesses");

KNOB<BOOL> KnobReverseExecution(KNOB_MODE_WRITEONCE, "pintool",
		"-rx", "1", "enable reverse execution");

/*
 * Input file
 */

ifstream infile;
ifstream dylibmapfile;

enum INPUTFILE_TYPE
{
	INPUT_PTPIN=0,
	INPUT_PERF=1,
};

enum INPUTFILE_TYPE infiletype;

/*
 * log file
 */
bool beginLog = true;
ofstream _logfile;
string global_tsc;

#define logfile(x) \
	if(x>=_DEBUG_) _logfile

/*
 * Global Variables
 */

#define REPORT_ALL_INSTRUCTION_RECOVRY 0

UINT64 ins_count = 0;
UINT64 ins_skip_count = 0;
//the number of memory operations
UINT64 ins_memop_count = 0;
//the number of skipped memory operations
UINT64 ins_memop_skip_count = 0;


/*
 * true when the dynamic link library memory map file is provided
 * otherwise false
 */
BOOL provided_dylib_map;

ADDRINT mainImageHighAddress;
ADDRINT mainImageLowAddress;

/*
 * recorder for next instruction address
 * currentip,nextip
 */
map<ADDRINT,ADDRINT> ipmap;

CONTEXT tgtCtxt;

//store the return address
vector<ADDRINT> callstack;

//input/output file register file sequence
#define TOTAL_REGS 19
REG regSeq[TOTAL_REGS]=
{
	REG_RFLAGS,
	REG_INST_PTR,
	REG_RIP,

	REG_RAX,
	REG_RBX,
	REG_RCX,
	REG_RDX,
	REG_RSI,
	REG_RDI,
	REG_RBP,
	REG_RSP,

	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_R13,
	REG_R14,
	REG_R15
};

////////////////////////////////////////////////////////////////
/*
 * Register Availability Calculator
 */
struct AVMatrix
{
	//general purpose registers
	unsigned int rax:1;
	unsigned int eax:1;
	unsigned int ax:1;
	unsigned int ah:1;
	unsigned int al:1;

	unsigned int rbx:1;
	unsigned int ebx:1;
	unsigned int bx:1;
	unsigned int bh:1;
	unsigned int bl:1;

	unsigned int rcx:1;
	unsigned int ecx:1;
	unsigned int cx:1;
	unsigned int ch:1;
	unsigned int cl:1;

	unsigned int rdx:1;
	unsigned int edx:1;
	unsigned int dx:1;
	unsigned int dh:1;
	unsigned int dl:1;

	//index registers
	unsigned int rsi:1;
	unsigned int esi:1;
	unsigned int si:1;
	unsigned int sil:1;

	unsigned int rdi:1;
	unsigned int edi:1;
	unsigned int di:1;
	unsigned int dil:1;

	//pointer registers
	unsigned int rbp:1;
	unsigned int ebp:1;
	unsigned int bp:1;
	unsigned int bpl:1;

	unsigned int rsp:1;
	unsigned int esp:1;
	unsigned int sp:1;
	unsigned int spl:1;

//////////////////////
//other GPs for x86_64

	unsigned int r8:1;
	unsigned int r8d:1;
	unsigned int r8w:1;
	unsigned int r8b:1;

	unsigned int r9:1;
	unsigned int r9d:1;
	unsigned int r9w:1;
	unsigned int r9b:1;

	unsigned int r10:1;
	unsigned int r10d:1;
	unsigned int r10w:1;
	unsigned int r10b:1;

	unsigned int r11:1;
	unsigned int r11d:1;
	unsigned int r11w:1;
	unsigned int r11b:1;

	unsigned int r12:1;
	unsigned int r12d:1;
	unsigned int r12w:1;
	unsigned int r12b:1;

	unsigned int r13:1;
	unsigned int r13d:1;
	unsigned int r13w:1;
	unsigned int r13b:1;

	unsigned int r14:1;
	unsigned int r14d:1;
	unsigned int r14w:1;
	unsigned int r14b:1;

	unsigned int r15:1;
	unsigned int r15d:1;
	unsigned int r15w:1;
	unsigned int r15b:1;

//////////////////////
// special register
	unsigned int rflags:1;
	unsigned int rip:1;

};


AVMatrix _avm={1,};
//AVMatrix _naavm={0,};//NA state

BOOL AllRegsNA()
{
	//leave rip and rflags
	logfile(0)<<"Reg Status:";
	bool r = true;
	for(int i=0;i<68;i++)
	{
		if(((unsigned int*)&_avm)[i]==1)
		{
			logfile(0)<<"o";
			r = false;
		}else
		{
			logfile(0)<<"x";
		}
		if((i+1)%5==0)
		{
			logfile(0)<<" ";
		}
	}
	logfile(0)<<endl;
	return r;
}


/*
 * operands for inspection
 */

struct Ins_MEMI
{
	ADDRINT * address;
	UINT32 size;
};

struct Ins_OPERAND
{
	PIN_REGISTER ip;
	ADDRINT nextip;

	unsigned int rRegCnt;
	unsigned int wRegCnt;
	unsigned int rwMemCnt;

	vector<REG> rRegs;
	vector<REG> wRegs;

	vector<Ins_MEMI> rMems;
	vector<Ins_MEMI> wMems;
};

/*
 * current instruction
 * -------
 * instruction identifier
 * instruction buffer;
 */
struct Ins_OPERAND opbuf;

#if _USE_MMM_
/*
 * TODO: memory object manager
 * record what is available
 * start: mm->[|]
 *     write ins as NA, mm->[|]
 *     write ins as AV, add addr to mm
 */
std::list<ADDRINT*> mm;
#endif

////////////////////////////////////////////////////////////////////////
//TODO: replace with DU-UD chain
/*
 * ctxt entry info for ReverseExecution
 */

struct ReverseExecutionSavedCTXT
{
	//register
	REG reg;
	//available matrix
	AVMatrix avm;
	//pointer to trace;
	int tracefp_pos;
	//context information
	CONTEXT ctxt;
	//time stamp, for which instruction encountered first
	long long ts;
	/////////////////////////////////////////////////
	//statistics
	UINT64 ins_count;
	UINT64 ins_skip_count;
	//the number of memory operations
	UINT64 ins_memop_count;
	//the number of skipped memory operations
	UINT64 ins_memop_skip_count;
};

ReverseExecutionSavedCTXT rxctxt_raw[]=
{
	{REG_FLAGS, {0,}, -1,},

	//we will never lost RIP
	{REG_INST_PTR, {0, }, -1},
	{REG_RIP, {0, }, -1},
	////////////////////////
	
	{REG_RAX, {0, }, -1},
	{REG_RBX, {0, }, -1},
	{REG_RCX, {0, }, -1},
	{REG_RDX, {0, }, -1},
	{REG_RSI, {0, }, -1},
	{REG_RDI, {0, }, -1},
	{REG_RBP, {0, }, -1},
	{REG_RSP, {0, }, -1},

	{REG_R8, {0, }, -1},
	{REG_R9, {0, }, -1},
	{REG_R10, {0, }, -1},
	{REG_R11, {0, }, -1},
	{REG_R12, {0, }, -1},
	{REG_R13, {0, }, -1},
	{REG_R14, {0, }, -1},
	{REG_R15, {0, }, -1},
};

map<REG, ReverseExecutionSavedCTXT*> rxctxt;

#define INITIALIZE_RXCTXT \
	for(int i=0;i<TOTAL_REGS;i++) \
	{\
		rxctxt[regSeq[i]] = &rxctxt_raw[i];\
		rxctxt[regSeq[i]]->ts = -1;\
	}

////////////////////////////////////////////////////////////////////////////////////
#if 0
// DU-UD chain provides better support for reverse execution
// the trace is separated by BWAS entry,
// when we hit BWAS entry, we try to look at the trace to see if
// any instruction with NA register can be recovered.
// After that. the trace is dumpped into file.
// and the simulator start over from current BWAS entry

/*
 * DU-UD chain
 */

struct use_register
{
	//register
	REG reg;
	//define, position in it's saved vector
	int def;
};

struct def_register
{
	//register
	REG reg;
};

struct du_instruction
{
	//the instruction itself
	INS instruction;
	//used registers
	vector<use_register> ruse;
	//defined registers
	vector<def_register> rdef;
	//current context
	CONTEXT ctxt;
	//available matrix
	AVMatrix avm;
	//pointer to trace;
	int tracefp_pos;
	//time stamp
	long long ts;
	/////////////////////////////////////////////////
	//statistics
	UINT64 ins_count;
	UINT64 ins_skip_count;
	//the number of memory operations
	UINT64 ins_memop_count;
	//the number of skipped memory operations
	UINT64 ins_memop_skip_count;

};

vector<du_instruction> du_trace;

#endif

/////////////////////////////////////////////////////////////////////////////////////////
//Helper functions

string Val2Str(const void* value, unsigned int size)
{
	stringstream sstr;
	sstr << hex << setfill('0') << setw(2);
	const unsigned char* cval = (const unsigned char*)value;
	// Traverse cval from end to beginning since the MSB is in the last block of cval.
	while (size)
	{
		--size;
		sstr << setfill('0') << setw(2) << (unsigned int)cval[size];
	}
	return string("0x")+sstr.str();
}

/*
 * print current img
 */
#if 0
static VOID RIP2IMG(const CONTEXT * ctxt, int debug_level)
{
	ADDRINT currentip;
	PIN_GetContextRegval( ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&currentip));
	PIN_LockClient();
	if(IMG_FindByAddress(currentip)!=IMG_Invalid())
	{
		logfile(debug_level)<<"Is in IMG:"<<IMG_Name(IMG_FindByAddress(currentip))<<endl;
	}else{
		logfile(debug_level)<<"IMG: invalid"<<endl;
	}
	logfile(debug_level)<<"function:"<<RTN_FindNameByAddress(currentip)<<endl;
	PIN_UnlockClient();
}
#endif

/*
 * dump register to string
 */

string dr(CONTEXT * ctxt, REG reg)
{
	UINT size = REG_Size(reg);
	PIN_REGISTER tgtreg;
	PIN_GetContextRegval( ctxt, reg, reinterpret_cast<UINT8*>(&tgtreg));

	return Val2Str(&tgtreg, size);
}

inline VOID DumpReg(const CONTEXT * ctxt, REG reg, int dbg_level)
{
	UINT size = REG_Size(reg);
	PIN_REGISTER tgtreg;
	PIN_GetContextRegval( ctxt, reg, reinterpret_cast<UINT8*>(&tgtreg));

	logfile(dbg_level) <<REG_StringShort(reg)<<": "<< Val2Str(&tgtreg, size) <<endl;
#if 0
	if(reg==REG_INST_PTR)
	{
		RIP2IMG(ctxt, dbg_level);
	}
#endif
}
////////////////////////////////////////////////////////////////////////////////////////

/*
 * Report Statistict
 */

/*
 * set only when need report and the arch state is not surpressed
 */
BOOL ReportAndRestore = true;

VOID ReportStat(BOOL oride)
{
	//if(oride)
	//	ReportAndRestore = true;
	//if(!ReportAndRestore)
	//	return;
	//if(ins_count<=1)
	//	return;
#if REPORT_ALL_INSTRUCTION_RECOVRY
	logfile(4)<<"ins skip/all="
			<<ins_skip_count
			<<"/"
			<<ins_count
			<<endl;
	ins_skip_count = 0;
	ins_count = 0;
#else
	logfile(4)<<"memop ins skip/all="
		<<ins_memop_skip_count
		<<"/"
		<<ins_memop_count
		<<endl;
	ins_memop_count = 0;
	ins_memop_skip_count = 0;
#endif
	ReportAndRestore = false;
}

/*
 * setup misc
 */
inline BOOL GetREGAVM(REG r, AVMatrix& avm)
{
	switch(r)
	{
/////////////
//A
		case(REG_RAX):
			return avm.rax;
		case(REG_EAX):
			return avm.eax;
		case(REG_AX):
			return avm.ax;
		case(REG_AH):
			return avm.ah;
		case(REG_AL):
			return avm.al;
/////////////
//B
		case(REG_RBX):
			return avm.rbx;
		case(REG_EBX):
			return avm.ebx;
		case(REG_BX):
			return avm.bx;
		case(REG_BH):
			return avm.bh;
		case(REG_BL):
			return avm.bl;
/////////////
//C
		case(REG_RCX):
			return avm.rcx;
		case(REG_ECX):
			return avm.ecx;
		case(REG_CX):
			return avm.cx;
		case(REG_CH):
			return avm.ch;
		case(REG_CL):
			return avm.cl;
/////////////
//D
		case(REG_RDX):
			return avm.rdx;
		case(REG_EDX):
			return avm.edx;
		case(REG_DX):
			return avm.dx;
		case(REG_DH):
			return avm.dh;
		case(REG_DL):
			return avm.dl;
//////////////
//SI
		case(REG_RSI):
			return avm.rsi;
		case(REG_ESI):
			return avm.esi;
		case(REG_SI):
			return avm.si;
		case(REG_SIL):
			return avm.sil;
//////////////
//DI
		case(REG_RDI):
			return avm.rdi;
		case(REG_EDI):
			return avm.edi;
		case(REG_DI):
			return avm.di;
		case(REG_DIL):
			return avm.dil;
//////////////
//BP
		case(REG_RBP):
			return avm.rbp;
		case(REG_EBP):
			return avm.ebp;
		case(REG_BP):
			return avm.bp;
		case(REG_BPL):
			return avm.bpl;
//////////////
//SP
		case(REG_RSP):
			return avm.rsp;
		case(REG_ESP):
			return avm.esp;
		case(REG_SP):
			return avm.sp;
		case(REG_SPL):
			return avm.spl;
///////////////
//GP for x86_64
		case(REG_R8):
			return avm.r8;
		case(REG_R8D):
			return avm.r8d;
		case(REG_R8W):
			return avm.r8w;
		case(REG_R8B):
			return avm.r8b;

		case(REG_R9):
			return avm.r9;
		case(REG_R9D):
			return avm.r9d;
		case(REG_R9W):
			return avm.r9w;
		case(REG_R9B):
			return avm.r9b;

		case(REG_R10):
			return avm.r10;
		case(REG_R10D):
			return avm.r10d;
		case(REG_R10W):
			return avm.r10w;
		case(REG_R10B):
			return avm.r10b;

		case(REG_R11):
			return avm.r11;
		case(REG_R11D):
			return avm.r11d;
		case(REG_R11W):
			return avm.r11w;
		case(REG_R11B):
			return avm.r11b;

		case(REG_R12):
			return avm.r12;
		case(REG_R12D):
			return avm.r12d;
		case(REG_R12W):
			return avm.r12w;
		case(REG_R12B):
			return avm.r12b;

		case(REG_R13):
			return avm.r13;
		case(REG_R13D):
			return avm.r13d;
		case(REG_R13W):
			return avm.r13w;
		case(REG_R13B):
			return avm.r13b;

		case(REG_R14):
			return avm.r14;
		case(REG_R14D):
			return avm.r14d;
		case(REG_R14W):
			return avm.r14w;
		case(REG_R14B):
			return avm.r14b;

		case(REG_R15):
			return avm.r15;
		case(REG_R15D):
			return avm.r15d;
		case(REG_R15W):
			return avm.r15w;
		case(REG_R15B):
			return avm.r15b;
//////////////////////
// special registers
		case(REG_RFLAGS):
			return avm.rflags;
		case(REG_RIP):
			return avm.rip;
////////////////////
// always return true for segment registers
		case(REG_SEG_CS):
			return true;
		case(REG_SEG_SS):
			return true;
		case(REG_SEG_DS):
			return true;
		case(REG_SEG_ES):
			return true;
		case(REG_SEG_FS):
			return true;
		case(REG_SEG_GS):
			return true;
		default:
			break;
	}
///////////////////////
// other unhandled registers
	logfile(0)<<"F...! ";
	return false;
}

inline REG extendRegister(REG r)
{
	switch(r)
	{
/////////////
//A
		case(REG_RAX):
		case(REG_EAX):
		case(REG_AX):
		case(REG_AH):
		case(REG_AL):
			return REG_RAX;
			break;
/////////////
//B
		case(REG_RBX):
		case(REG_EBX):
		case(REG_BX):
		case(REG_BH):
		case(REG_BL):
			return REG_RBX;
			break;
/////////////
//C
		case(REG_RCX):
		case(REG_ECX):
		case(REG_CX):
		case(REG_CH):
		case(REG_CL):
			return REG_RCX;
			break;
/////////////
//D
		case(REG_RDX):
		case(REG_EDX):
		case(REG_DX):
		case(REG_DH):
		case(REG_DL):
			return REG_RDX;
			break;
//////////////
//SI
		case(REG_RSI):
		case(REG_ESI):
		case(REG_SI):
		case(REG_SIL):
			return REG_RSI;
			break;
//////////////
//DI
		case(REG_RDI):
		case(REG_EDI):
		case(REG_DI):
		case(REG_DIL):
			return REG_RDI;
			break;
//////////////
//BP
		case(REG_RBP):
		case(REG_EBP):
		case(REG_BP):
		case(REG_BPL):
			return REG_RBP;
			break;
//////////////
//SP
		case(REG_RSP):
		case(REG_ESP):
		case(REG_SP):
		case(REG_SPL):
			return REG_RSP;
			break;
///////////////
//GP r8~r15 for x86_64
		case(REG_R8):
		case(REG_R8D):
		case(REG_R8W):
		case(REG_R8B):
			return REG_R8;
			break;

		case(REG_R9):
		case(REG_R9D):
		case(REG_R9W):
		case(REG_R9B):
			return REG_R9;
			break;

		case(REG_R10):
		case(REG_R10D):
		case(REG_R10W):
		case(REG_R10B):
			return REG_R10;
			break;

		case(REG_R11):
		case(REG_R11D):
		case(REG_R11W):
		case(REG_R11B):
			return REG_R11;
			break;

		case(REG_R12):
		case(REG_R12D):
		case(REG_R12W):
		case(REG_R12B):
			return REG_R12;
			break;

		case(REG_R13):
		case(REG_R13D):
		case(REG_R13W):
		case(REG_R13B):
			return REG_R13;
			break;

		case(REG_R14):
		case(REG_R14D):
		case(REG_R14W):
		case(REG_R14B):
			return REG_R14;
			break;

		case(REG_R15):
		case(REG_R15D):
		case(REG_R15W):
		case(REG_R15B):
			return REG_R15;
			break;

//////////////////////
// special registers
//FIXME!
		case(REG_RFLAGS):
			return REG_RFLAGS;
			break;
//FIXME!
		case(REG_RIP):
			return REG_RIP;
			break;
		default:
			break;
	}
///////////////////////
// other unhandled registers
	return REG_INVALID_;
}

inline VOID SetOneState(REG r, AVMatrix& avm,unsigned int t)
{
	switch(r)
	{
/////////////
//A
		case(REG_RAX):
		case(REG_EAX):
		case(REG_AX):
		case(REG_AH):
		case(REG_AL):
			avm.rax = t;
			avm.eax = t;
			avm.ax = t;
			avm.ah = t;
			avm.al = t;
			break;
/////////////
//B
		case(REG_RBX):
		case(REG_EBX):
		case(REG_BX):
		case(REG_BH):
		case(REG_BL):
			avm.rbx = t;
			avm.ebx = t;
			avm.bx = t;
			avm.bh = t;
			avm.bl = t;
			break;
/////////////
//C
		case(REG_RCX):
		case(REG_ECX):
		case(REG_CX):
		case(REG_CH):
		case(REG_CL):
			avm.rcx = t;
			avm.ecx = t;
			avm.cx = t;
			avm.ch = t;
			avm.cl = t;
			break;
/////////////
//D
		case(REG_RDX):
		case(REG_EDX):
		case(REG_DX):
		case(REG_DH):
		case(REG_DL):
			avm.rdx = t;
			avm.edx = t;
			avm.dx = t;
			avm.dh = t;
			avm.dl = t;
			break;
//////////////
//SI
		case(REG_RSI):
		case(REG_ESI):
		case(REG_SI):
		case(REG_SIL):
			avm.rsi = t;
			avm.esi = t;
			avm.si = t;
			avm.sil = t;
			break;
//////////////
//DI
		case(REG_RDI):
		case(REG_EDI):
		case(REG_DI):
		case(REG_DIL):
			avm.rdi = t;
			avm.edi = t;
			avm.di = t;
			avm.dil = t;
			break;
//////////////
//BP
		case(REG_RBP):
		case(REG_EBP):
		case(REG_BP):
		case(REG_BPL):
			avm.rbp = t;
			avm.ebp = t;
			avm.bp = t;
			avm.bpl = t;
			break;
//////////////
//SP
		case(REG_RSP):
		case(REG_ESP):
		case(REG_SP):
		case(REG_SPL):
			avm.rsp = t;
			avm.esp = t;
			avm.sp = t;
			avm.spl = t;
			break;
///////////////
//GP r8~r15 for x86_64
		case(REG_R8):
		case(REG_R8D):
		case(REG_R8W):
		case(REG_R8B):
			avm.r8 = t;
			avm.r8d = t;
			avm.r8w = t;
			avm.r8b = t;
			break;

		case(REG_R9):
		case(REG_R9D):
		case(REG_R9W):
		case(REG_R9B):
			avm.r9 = t;
			avm.r9d = t;
			avm.r9w = t;
			avm.r9b = t;
			break;

		case(REG_R10):
		case(REG_R10D):
		case(REG_R10W):
		case(REG_R10B):
			avm.r10 = t;
			avm.r10d = t;
			avm.r10w = t;
			avm.r10b = t;
			break;

		case(REG_R11):
		case(REG_R11D):
		case(REG_R11W):
		case(REG_R11B):
			avm.r11 = t;
			avm.r11d = t;
			avm.r11w = t;
			avm.r11b = t;
			break;

		case(REG_R12):
		case(REG_R12D):
		case(REG_R12W):
		case(REG_R12B):
			avm.r12 = t;
			avm.r12d = t;
			avm.r12w = t;
			avm.r12b = t;
			break;

		case(REG_R13):
		case(REG_R13D):
		case(REG_R13W):
		case(REG_R13B):
			avm.r13 = t;
			avm.r13d = t;
			avm.r13w = t;
			avm.r13b = t;
			break;

		case(REG_R14):
		case(REG_R14D):
		case(REG_R14W):
		case(REG_R14B):
			avm.r14 = t;
			avm.r14d = t;
			avm.r14w = t;
			avm.r14b = t;
			break;

		case(REG_R15):
		case(REG_R15D):
		case(REG_R15W):
		case(REG_R15B):
			avm.r15 = t;
			avm.r15d = t;
			avm.r15w = t;
			avm.r15b = t;
			break;

//////////////////////
// special registers
//FIXME!
		case(REG_RFLAGS):
			avm.rflags = t;
			break;
//FIXME!
		case(REG_RIP):
			avm.rip = t;
			break;

		default:
			logfile(0)<<" F...! ";
			break;
	}
///////////////////////
// other unhandled registers
	logfile(0)<<endl;
}

/*
 * set registers to not available
 * - record what register is written,
 *   as well as avmatrix and context
 */
VOID SetAllTgtRegNA(const CONTEXT * ctxt)
{
	for(std::vector<REG>::iterator it = opbuf.wRegs.begin();
			it!=opbuf.wRegs.end();
			it++)
	{
		logfile(1)<<"set REG:"<<REG_StringShort(*it)<<" to NA "<<endl;
		SetOneState(*it,_avm,0);
	}

	if(!KnobReverseExecution)
		return;

	static struct timeval ts;
	gettimeofday(&ts,NULL);
	long long timestamp = ts.tv_sec * 1000000LL + ts.tv_usec;
	logfile(1)<<"Wall time:"<<dec<<timestamp<<endl;
	for(std::vector<REG>::iterator it = opbuf.wRegs.begin();
			it!=opbuf.wRegs.end();
			it++)
	{
		logfile(4)<<"Setting REG: "<<REG_StringShort(*it)<<endl;

		//extend register
		//eg: dx,edx -> rdx
		REG reg = extendRegister(*it);

		map<REG,ReverseExecutionSavedCTXT*>::iterator rxctxtit
			= rxctxt.find(reg);
		if(rxctxtit != rxctxt.end())
		{
			//save timestamp
			rxctxtit->second->ts = timestamp;
			//save register available status
			rxctxtit->second->avm = _avm;
			//save trace file 
			rxctxtit->second->tracefp_pos = infile.tellg();
			//save context
			PIN_SaveContext(ctxt, &(rxctxtit->second->ctxt));
			//save statistics
			rxctxtit->second->ins_count = ins_count;
			rxctxtit->second->ins_skip_count = ins_skip_count;
			rxctxtit->second->ins_memop_count = ins_memop_count;
			rxctxtit->second->ins_memop_skip_count = ins_memop_skip_count;

			//logfile(4)<<"Verify: current ctxt IP:";
			//DumpReg(ctxt, REG_RIP, 4);
			//logfile(4)<<"Verify: copied ctxt IP:";
			//DumpReg(&(rxctxtit->second->ctxt), REG_RIP, 4);
		}else
		{
			logfile(4)<<"Not Found!!?"<<endl;
		}
	}
}

/*
 * set mem to not available
 */
VOID SetAllTgtMEMNA()
{
#if _USE_MMM_
#if 0
	for(std::vector<Ins_MEMI>::iterator it = opbuf.wMems.begin();
			it!=opbuf.wMems.end();
			it++)
	{
		logfile(2)<<"set wMEM @ "<<hex<<(*it).address<<dec<<" to NA"<<endl;
		list<ADDRINT*>::iterator xit = find(mm.begin(),mm.end(),(*it).address);
		if(xit!=mm.end())
		{
			mm.erase(xit);
		}
		//if(xit==mm.end())
		//{
		//	mm.push_back((*it).address);
		//}
	}
#endif
	mm.clear();
#endif
}

/*
 * set all [ mem + reg ] to not available
 */
VOID SetAllTgtNA(const CONTEXT * ctxt)
{
	SetAllTgtRegNA(ctxt);
	SetAllTgtMEMNA();
}

/*
 * set all registers to available
 * remove the register NA state from rxctxt
 */
inline VOID SetAllTgtAvailable()
{
	for(std::vector<REG>::iterator it = opbuf.wRegs.begin();
			it!=opbuf.wRegs.end();
			it++)
	{
		logfile(2)<<"set REG:"<<REG_StringShort(*it)<<" to Available ";
		SetOneState(*it,_avm,1);
		//remove NA state from rxctxt
		//calculate superset of *it
		map<REG,ReverseExecutionSavedCTXT*>::iterator rxctxtit
			= rxctxt.find(extendRegister(*it));
		if(rxctxtit!=rxctxt.end())
		{
			rxctxtit->second->ts = -1;
		}

	}
}


/////////////////////////////////////////////////////////////////



/*
 * Print Help Message
 */

INT32 Usage()
{
	cerr << "Guided Program Execution.\n";

	cerr << KNOB_BASE::StringKnobSummary();

	cerr << endl;

	return -1;
}

////////////////////////////////////////////////////////////////
/*
 * once we recovered full architecture status,
 * search through the list to see if there is any chance to restart
 * from where Registers are set to NA
 */
VOID CheckReverseExecution(CONTEXT * ctxt)
{
	if(!KnobReverseExecution)
		return;

	vector<REG> rcand;
	rcand.push_back(regSeq[0]);

	
	
	//find out who is the first on the Time axis
	for(int i=1;i<TOTAL_REGS;i++)
	{
		logfile(0)<<"Checking :"
			<<REG_StringShort(regSeq[i])
			<<" : WT : "
			<<rxctxt[regSeq[i]]->ts
			<<endl;
		if(rxctxt[regSeq[i]]->ts == -1)
		{
			continue;
		}
		if(rxctxt[rcand[0]]->ts == -1)
		{
			rcand[0] = regSeq[i];
			continue;
		}
		if(rxctxt[regSeq[i]]->ts == rxctxt[rcand[0]]->ts)
		{
			rcand.push_back(regSeq[i]);
		}else if(rxctxt[regSeq[i]]->ts < rxctxt[rcand[0]]->ts)
		{
			rcand.clear();
			rcand.push_back(regSeq[i]);
		}
	}

	if(rxctxt[rcand[0]]->ts<=0)
		return;

	logfile(2)<<"REVEXEC: As far as we know, [";
	for(unsigned int i=0;i<rcand.size();i++)
	{
		logfile(2)<<REG_StringShort(rcand[i])<<",";
	}
	logfile(2)<<" ] is written at Time: "
		<<rxctxt[rcand[0]]->ts
		<<endl;
	//copy register values in current context to rxctxt
	logfile(2)<<"Recovering "<<rcand.size()<<" register(s)."
		<<" and restart execution @ ";
	CONTEXT * tgtCtxt = &(rxctxt[rcand[0]]->ctxt);
	ADDRINT regdata;
	for(unsigned int i=0;i<rcand.size();i++)
	{
		PIN_GetContextRegval(ctxt,
				rcand[i],
				reinterpret_cast<UINT8*>(&regdata) );
		PIN_SetContextRegval(tgtCtxt,
				rcand[i],
				reinterpret_cast<UINT8*>(&regdata) );
	}
	//goto it's next ip if possible
	PIN_GetContextRegval(tgtCtxt,
			REG_RIP,
			reinterpret_cast<UINT8*>(&regdata) );
	regdata = ipmap[regdata];
	PIN_SetContextRegval(tgtCtxt,
			REG_RIP,
			reinterpret_cast<UINT8*>(&regdata) );

	DumpReg(tgtCtxt, REG_RIP, 2);
	

	//recover avmatrix
	//and set recovered register to available
	logfile(2)<<"Resetting register's available status"<<endl;
	_avm = rxctxt[rcand[0]]->avm;
	for(unsigned int i=0;i<rcand.size();i++)
	{
		SetOneState(rcand[i],_avm,1);
	}

	logfile(2)<<"Resetting trace file pos"<<endl;
	//recover tracefile pointer
	infile.seekg(rxctxt[rcand[0]]->tracefp_pos);
	logfile(2)<<"Resetting statistics"<<endl;
	ins_count = rxctxt[rcand[0]]->ins_count;
	ins_skip_count = rxctxt[rcand[0]]->ins_skip_count;
	ins_memop_count = rxctxt[rcand[0]]->ins_memop_count;
	ins_memop_skip_count = rxctxt[rcand[0]]->ins_memop_skip_count;

	//squash rxctxt
	//FIXME: maybe it is useful?
	logfile(2)<<"Squashing rxctxt"<<endl;
	for(int i=0;i<TOTAL_REGS;i++)
	{
		rxctxt[regSeq[i]]->ts = -1;
	}
	PIN_ExecuteAt(tgtCtxt);
}



////////////////////////////////////////////////////////////////////////

VOID LoadReg(CONTEXT * ctxt, REG reg)
{
	unsigned long regdata;

	if(infile.eof())
	{
		logfile(3)<<"trace file exhausted. exiting."<<endl;
		PIN_ExitApplication(0);
	}
	infile>>hex>>regdata;
	PIN_SetContextRegval(ctxt, reg, reinterpret_cast<UINT8*>(&regdata) );
	//DumpReg(ctxt, reg, 0);
}

/*
 * Load Register file and setup CONTEXT
 * shared by pt_pin and perf trace
 * this part has the same structure
 */

VOID LoadRegsFromFile(CONTEXT * ctxt)
{
	for(int i=0;i<TOTAL_REGS;i++)
		LoadReg(ctxt, regSeq[i]);

	logfile(0)<<"Replaced register files.\n"
		<<"New IP:";
	DumpReg(ctxt, REG_INST_PTR, 0);

	if ((KnobDrop==0) || ((rand() % 100 ) >= KnobDrop) )
	{
		//reset avmatrix
		memset(&_avm,0xFF,sizeof(AVMatrix));
		//ReportStat(true);
	}
	PIN_ExecuteAt(ctxt);
}

/*
 * this is for pt_pin generated trace file
 */
VOID SkipRegSet(CONTEXT * ctxt)
{
	unsigned long regdata;
	for(int i=0;i<TOTAL_REGS;i++)
		infile>>hex>>regdata;
}

/*
 * this is for perf generated trace file
 *     CONTEXT * ctxt => current context
 *     BOOL verify_address => verify branch from address
 */

VOID SkipRegsOrBrDest(CONTEXT * ctxt, BOOL verify_address)
{
	int top_lastpos = infile.tellg();

	string entry_type;
	infile>>entry_type;
	string tsc;
	infile >>tsc;//time stamp

	if(entry_type=="BWAS")
	{
		CONTEXT tgtCtxt;
		for(int i=0;i<TOTAL_REGS;i++)
			LoadReg(&tgtCtxt, regSeq[i]);
		//verify whether the address is matched or not
		if(verify_address)
		{
			unsigned long currentip;
			unsigned long candidateip;
			PIN_GetContextRegval( ctxt, REG_RIP, reinterpret_cast<UINT8*>(&currentip));
			PIN_GetContextRegval( &tgtCtxt, REG_RIP, reinterpret_cast<UINT8*>(&candidateip));
			//current ctxt.RIP should equal to tgtCtxt.RIP
			if( currentip != candidateip)
			{
				//match failed
				//rewind file descriptor
				infile.seekg(top_lastpos);
				logfile(0)<<"     match fail @ tsc : "<<tsc<<" current rip:"<<hex<<currentip<<dec<<endl;
				return;
			}
		}
		logfile(0)<<"SkipRegsOrBrDest: BWAS  tsc: "<<tsc;
		//copy register file from ctxt to tgtCtxt
		for(int i=0;i<TOTAL_REGS;i++)
		{
			PIN_REGISTER treg;
			PIN_GetContextRegval( &tgtCtxt, regSeq[i], reinterpret_cast<UINT8*>(&treg) );
			PIN_SetContextRegval( ctxt, regSeq[i], reinterpret_cast<UINT8*>(&treg) );
		}
		//reset avmatrix since all registers are restored
		memset(&_avm,0xFF,sizeof(AVMatrix));
		//ReportStat(true);
		//update global tsc
		global_tsc = tsc;
		//check whether we can restart execution
		CheckReverseExecution(ctxt);
		//if returned, we do not need to restart execution
		//i.e. we will never go back
		ReportStat(true);
	}else if(entry_type=="BWOAS")
	{
		unsigned long regdata;
		infile>>hex>>regdata;// should read from ip
		//verify whether the from_ip is matched or not
		if(verify_address)
		{
			unsigned long currentip;
			PIN_GetContextRegval( ctxt, REG_RIP, reinterpret_cast<UINT8*>(&currentip));
			//current ctxt.RIP should equal to regdata, which is from_ip
			if( currentip != regdata)
			{
				//match failed
				//rewind file descriptor
				infile.seekg(top_lastpos);
				logfile(0)<<"     match fail @ tsc : "<<tsc<<" current rip:"<<hex<<currentip<<dec<<endl;
				return;
			}
		}
		infile>>hex>>regdata;
		//update global tsc
		global_tsc = tsc;
	}else if(infile.eof())
	{
		logfile(3)<<"trace file exhausted. exiting."<<endl;
		PIN_ExitApplication(0);
	}else
	{
		logfile(3)<<"Entry mismatch!"<<endl;
		logfile(3)<<"Got type:"<<entry_type<<endl;
		PIN_ExitApplication(-1);
	}
}

/*
 * read entry from perf generated logfile
 * - BWOAS, branch entry without architecture state
 * - BWAS, entry with architecture state
 *
 *   CONTEXT * ctxt => current context
 *   BOOL verify_address => verify branch from address
 *
 *
 * we are currently ignoring code in dynamic linked libraries,
 * for that the dynamic loader is not deterministic and PIN's replay
 * mechanism does not work properly.
 * If we encountered IP in such code region,
 * just skip through to the next entry
 *
 */

VOID SetupRegsOrBrDestFromFile(CONTEXT * ctxt,
		BOOL verify_address,
		BOOL donotreturn,
		BOOL incallback)
{
	/*
	 * when verify_address is set
	 * return to top_lastpos if match fail
	 */
	int top_lastpos;
	string entry_type;
	string tsc;

next_one:
	if(infile.eof())
	{
		logfile(3)<<"trace file exhausted. exiting."<<endl;
		PIN_ExitApplication(0);
	}
	top_lastpos = infile.tellg();
	infile>>entry_type;
	infile>>tsc;

	if(entry_type=="BWAS")
	{
		CONTEXT tgtCtxt;
		for(int i=0;i<TOTAL_REGS;i++)
			LoadReg(&tgtCtxt, regSeq[i]);
		//verify whether the address is matched or not
		if(verify_address)
		{
			unsigned long currentip;
			unsigned long candidateip;
			PIN_GetContextRegval( ctxt, REG_RIP, reinterpret_cast<UINT8*>(&currentip));
			PIN_GetContextRegval( &tgtCtxt, REG_RIP, reinterpret_cast<UINT8*>(&candidateip));
			//current ctxt.RIP should equal to tgtCtxt.RIP
			if( currentip != candidateip)
			{
				//match failed
				//rewind file descriptor
				infile.seekg(top_lastpos);
				logfile(0)<<"     match fail @ tsc : "<<tsc<<" current rip:"<<hex<<currentip<<dec<<endl;
				return;
			}
		}
		logfile(0)<<"SetupRegsOrBrDestFromFile: BWAS  tsc: "<<tsc;
		//copy register file from ctxt to tgtCtxt
		for(int i=0;i<TOTAL_REGS;i++)
		{
			PIN_REGISTER treg;
			PIN_GetContextRegval( &tgtCtxt, regSeq[i], reinterpret_cast<UINT8*>(&treg) );
			PIN_SetContextRegval( ctxt, regSeq[i], reinterpret_cast<UINT8*>(&treg) );
		}
		logfile(0)<<" ip:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		//////////////////////////////////////////////////////
		//TODO:check whether the destination address is located in the right binary image
		ADDRINT jmptoip;
		PIN_GetContextRegval( &tgtCtxt, REG_RIP, reinterpret_cast<UINT8*>(&jmptoip) );
		if((jmptoip>mainImageHighAddress) || (jmptoip<mainImageLowAddress))
		{
			logfile(3)<<"Target ip "
				<<hex
				<<jmptoip
				<<dec
				<<" is not in main executable ["
				<<hex
				<<mainImageLowAddress
				<<","
				<<mainImageHighAddress
				<<dec
				<<"],skip to next entry"<<endl;
			//clean up and restart
			verify_address = false;
			donotreturn = (!incallback)&&true;
			//set all registers to not available
			memset(&_avm,0x00,sizeof(AVMatrix));
			//squash stack
			callstack.clear();
			//squash reverse execution table
			INITIALIZE_RXCTXT;
			goto next_one;
		}

		//double check ip address is in a valid function
		if(RTN_FindNameByAddress(jmptoip)=="")
		{
			goto next_one;
		}

		//////////////////////////////////////////////////////
		//reset avmatrix since all registers are restored
		memset(&_avm,0xFF,sizeof(AVMatrix));
		//ReportStat(true);
		//update global tsc
		global_tsc = tsc;
		//check whether we can restart execution
		CheckReverseExecution(ctxt);
		//we are safe now, report statistics
		ReportStat(true);
		if(donotreturn)
			PIN_ExecuteAt(ctxt);//never return
	}else if(entry_type=="BWOAS")
	{
		unsigned long regdata;
		infile>>hex>>regdata;// should read from ip
		//verify whether the from_ip is matched or not
		if(verify_address)
		{
			unsigned long currentip;
			PIN_GetContextRegval( ctxt, REG_RIP, reinterpret_cast<UINT8*>(&currentip));
			//current ctxt.RIP should equal to regdata, which is from_ip
			if( currentip != regdata)
			{
				//match failed
				//rewind file descriptor
				infile.seekg(top_lastpos);
				logfile(0)<<"     match fail @ tsc : "<<tsc<<" current rip:"<<hex<<currentip<<dec<<endl;
				return;
			}
		}
		logfile(0)<<"SetupRegsOrBrDestFromFile: BWOAS tsc: "<<tsc;
		//load RIP<ToIP>
		regdata=0x0;
		infile>>hex>>regdata;
		PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&regdata) );
		PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&regdata) );
		//FIXME? following BWAS will be handled before next instruction got executed?
		logfile(0)<<" ip:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		//////////////////////////////////////////////////////
		//TODO:check whether the destination address is located in the right binary image
		ADDRINT jmptoip;
		PIN_GetContextRegval( ctxt, REG_RIP, reinterpret_cast<UINT8*>(&jmptoip) );
		if((jmptoip>mainImageHighAddress) || (jmptoip<mainImageLowAddress))
		{
			logfile(3)<<"Target ip "
				<<hex
				<<jmptoip
				<<dec
				<<" is not in main executable ["
				<<hex
				<<mainImageLowAddress
				<<","
				<<mainImageHighAddress
				<<dec
				<<"],skip to next entry"<<endl;
			//clean up and restart
			verify_address = false;
			donotreturn = (!incallback) && true;
			//set all registers to not available
			memset(&_avm,0x00,sizeof(AVMatrix));
			//squash stack
			callstack.clear();
			//squash reverse execution table
			INITIALIZE_RXCTXT;
			goto next_one;
		}

		//double check ip address is in a valid function
		if(RTN_FindNameByAddress(jmptoip)=="")
		{
			goto next_one;
		}

		//////////////////////////////////////////////////////

		//update global tsc
		global_tsc = tsc;
		if(donotreturn)
			PIN_ExecuteAt(ctxt);//never return
	}else if(infile.eof())
	{
		logfile(3)<<"trace file exhausted. exiting."<<endl;
		PIN_ExitApplication(0);
	}else
	{
		logfile(3)<<"Entry mismatch!"<<endl;
		logfile(3)<<"Got type:"<<entry_type<<endl;
		PIN_ExitApplication(-1);
	}
}

/*
 * restart execution from current entry
 */

VOID restart_execution(CONTEXT * ctxt, BOOL donotreturn, BOOL incallback)
{
	//set all registers to not available
	memset(&_avm,0x00,sizeof(AVMatrix));
	//squash stack
	callstack.clear();
	//squash reverse execution table
	INITIALIZE_RXCTXT;
	SetupRegsOrBrDestFromFile(ctxt, false, donotreturn, incallback);
}

/*
 * called before main()
 */

VOID SwitchOnGuide(CONTEXT * ctxt)
{
	beginLog = true;

	logfile(2)<<"Hit main(), begin guided program execution."<<endl;

	if(infiletype==INPUT_PTPIN)
	{
		//this logfile is generated by ptpin
		//reset avmatrix
		memset(&_avm,0xFF,sizeof(AVMatrix));
		if(KnobJmpAt)
		{
			logfile(2)<<"JmpAt is set, do jmp at main()"<<endl;
			LoadRegsFromFile(ctxt);
		}
	}else if(infiletype==INPUT_PERF)
	{
		//this logfile is generated by perf
		if(KnobJmpAt)
		{
			logfile(2)<<"JmpAt is set, try do jmp at main()"<<endl;
			SetupRegsOrBrDestFromFile(ctxt, false, true, false);
		}else
		{
			memset(&_avm,0xFF,sizeof(AVMatrix));
		}
	}
}


/*
 * guide program execution using given log,
 * -----
 * reload all registers using given value
 * especially the flags register
 * If it is indirect branch, should replace the instruction with direct branch
 */
VOID guideBranch(CONTEXT * ctxt, ADDRINT currentip, ADDRINT nextip)
{
	if(!beginLog)
	{
		return;
	}

	ins_count++;

	//ReportStat(false);
	if(infiletype==INPUT_PTPIN)
	{
		LoadRegsFromFile(ctxt);
	}else if(infiletype==INPUT_PERF)
	{
		//if one branch is not taken it will not appear in perf generated trace.(BWOAS entry)
		//i.e. this branch is not taken, then we just go to next ip
		//verify the From_IP in the BWAS/BWOAS entry is the same as current one
		//if yes, guide execution using the one in entry,
		//otherwise, jump to nextip

		//if matched, never return
		SetupRegsOrBrDestFromFile(ctxt, true, true, false);
		//match failed
		logfile(1)<<"Branch(N): no matching entry in perf trace. currentip:";
		DumpReg(ctxt, REG_INST_PTR, 1);
		//jmp to next ip
		PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&nextip) );
		PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&nextip) );
		logfile(1)<<"Branch to nextip:";
		DumpReg(ctxt, REG_INST_PTR, 1);
		PIN_ExecuteAt(ctxt);
	}
}

/*
 * indirect call handler
 */
VOID guideIndirectCall(CONTEXT * ctxt, ADDRINT currentip, ADDRINT nextip)
{
	if(!beginLog)
	{
		return;
	}

	ins_count++;

	//logfile<<"can not handle indirect call at:";
	//DumpReg(ctxt, REG_INST_PTR);
	//PIN_ExitApplication(0);
	
	//FIXME!
	//indirect call dereference memory address which is prohibited.
	//fetch the target from trace file and call that address directly instead
	//SkipRegSet(ctxt);
	if(infiletype==INPUT_PTPIN)
	{
		logfile(0)<<"Try to handle indirect call at:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		logfile(0)<<"Call Stack Level:"<<callstack.size()<<endl;
		callstack.push_back(nextip);
		//ReportStat(false);
		LoadRegsFromFile(ctxt);
	}else if(infiletype==INPUT_PERF)
	{
		logfile(0)<<"Try to handle indirect call at:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		logfile(0)<<"Call Stack Level:"<<callstack.size()<<endl;
		callstack.push_back(nextip);
		//ReportStat(false);
		SetupRegsOrBrDestFromFile(ctxt, true, true, false);
		//entry mismatch, restart execution
		logfile(4)<<"Indirect branch WTF?!!! IP:";
		DumpReg(ctxt, REG_INST_PTR, 4);
		restart_execution(ctxt, true, false);
	}
}

/*
 * direct call handler
 */
VOID guideDirectCall(CONTEXT * ctxt, ADDRINT currentip, ADDRINT nextip, ADDRINT tgtip)
{
	if(!beginLog)
	{
		return;
	}

	/*
	 * rsp may be unavailable, which is bad
	 */
#if 1
	logfile(0)<<"transfer to indirect call handler - direct call at:";
	DumpReg(ctxt, REG_INST_PTR, 0);
	guideIndirectCall(ctxt,currentip,nextip);
#else
	if(infiletype==INPUT_PTPIN)
	{
		SkipRegSet(ctxt);
		logfile(0)<<"untouched direct call at:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		logfile(0)<<"Call Stack Level:"<<callstack.size()<<endl;
		callstack.push_back(nextip);
	}else if(infiletype==INPUT_PERF)
	{
		//FIXME!
		//there are junks in perf trace
		//first verify then throw away all garbage
		//the last one we want to throw must
		//have:
		//{
		//	"FromIP"=>currentip,
		//	"ToIP"=>tgtip,
		//}
		//If there is a matching 
		//BWAS entry, restore this bwas entry and execute this line
		logfile(0)<<"untouched direct call at:";
		DumpReg(ctxt, REG_INST_PTR, 0);
		SetupRegsOrBrDestFromFile(ctxt,true,false);
		logfile(0)<<"Call Stack Level:"<<callstack.size()<<endl;
		callstack.push_back(nextip);
		logfile(0)<<"Call Stack << 0x"<<hex<<nextip<<dec<<endl;
		//execute call instruction requires available of rsp.
		//if rsp is not available, then we can not execute
		//call instruction directly
		if(!GetREGAVM(REG_RSP,_avm))
		{
			logfile(0)<<"RSP is not available, translate call to jmp"<<endl;
			PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&tgtip) );
			PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&tgtip) );
			logfile(1)<<"Branch to nextip:";
			DumpReg(ctxt, REG_INST_PTR, 1);
			PIN_ExecuteAt(ctxt);
		}else
		{
			logfile(0)<<"RSP is available, execute this call"<<endl;
		}
	}
#endif
}



VOID guideRet(CONTEXT * ctxt)
{
	if(!beginLog)
		return;

	ins_count++;

	if(callstack.size()==0)
	{
		//no valid ret addr in stack
		//jmp to next known branch
		logfile(0)<<"Call Stack Level is 0, jmp to next branch point"<<endl;
		//ReportStat(false);
		if(infiletype==INPUT_PTPIN)
		{
			LoadRegsFromFile(ctxt);
		}else if(infiletype==INPUT_PERF)
		{
			logfile(4)<<"Ret 0 WTF?!!! IP:";
			DumpReg(ctxt, REG_INST_PTR, 0);
			//guide program execution using perf generated pt trace file
			//we are lost, restart from next entry
			restart_execution(ctxt, true, false);
		}
	}else
	{
		ADDRINT retip = callstack.back();
		callstack.pop_back();
		logfile(0)<<"Hit ret, Stack Level is "<<callstack.size()<<endl;

		if(infiletype==INPUT_PTPIN)
		{
			if(retip!=0)
			{
				PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&retip) );
				PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&retip) );
				PIN_ExecuteAt(ctxt);
			}
			LoadRegsFromFile(ctxt);
		}else if (infiletype==INPUT_PERF)
		{
			//guide program execution using perf generated pt trace file
			SetupRegsOrBrDestFromFile(ctxt, true, true, false);
			//FIXME:mismatched entry, PT aux data lost???
			//try to restore rip from stack
			PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&retip) );
			PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&retip) );
			PIN_ExecuteAt(ctxt);
			logfile(4)<<"Ret x WTF?!!! IP:";
			DumpReg(ctxt, REG_INST_PTR, 4);
			logfile(4)<<"Reset to current entry"<<endl;
			//we are lost, restart from next entry
			restart_execution(ctxt, true, false);
		}
	}
}

VOID guideSyscall(CONTEXT * ctxt, ADDRINT num, ADDRINT nextip)
{
	if(!beginLog)
	{
		return;
	}

	ins_count++;

	logfile(3)<<"Syscall: No "<<num<<" @ IP: ";
	DumpReg(ctxt, REG_RIP, 3);
	//NOTE: for perf generated trace file, syscalls are recorded
	//just skip such entry
	if(infiletype==INPUT_PERF)
	{
		SkipRegsOrBrDest(ctxt, true);
	}

	for(int i=0;i<TOTAL_REGS;i++)
		DumpReg(ctxt, regSeq[i], 5);

	//skip all syscall?
	switch(num)
	{
		case(0):
			logfile(5)<<"This is sys_read, skip"<<endl;
			goto end;
		case(3):
			logfile(5)<<"This is sys_close, skip"<<endl;
			goto end;
		case(8):
			logfile(5)<<"This is sys_lseek, skip"<<endl;
			goto end;
		case(10):
			logfile(5)<<"This is mprotect, skip"<<endl;
			goto end;
		case(11):
			logfile(5)<<"This is munmap, skip"<<endl;
			goto end;
		case(23):
			logfile(5)<<"This is select, skip"<<endl;
			goto end;
		case(28):
			logfile(5)<<"This is madvise, skip"<<endl;
			goto end;
		case(34):
			logfile(5)<<"This is pause, skip"<<endl;
			goto end;
		case(35):
			logfile(5)<<"This is nanosleep, skip"<<endl;
			goto end;
		case(87):
			logfile(5)<<"This is unlink, skip"<<endl;
			goto end;
		case(56):
			logfile(5)<<"This is sys_clone, skip"<<endl;
			goto end;
		case(202):
			logfile(5)<<"This is sys_futex, skip"<<endl;
			goto end;
		case(230):
			logfile(5)<<"This is clock_nanosleep, skip"<<endl;
			goto end;
		case(273):
			logfile(5)<<"This is sys_set_robust_list, skip"<<endl;
			goto end;
		default:
			goto rend;
	}
end:
	PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&nextip) );
	PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&nextip) );
	PIN_ExecuteAt(ctxt);

rend:
	return;

}

/*
 * dump all referenced memory address with TSC
 */
VOID dumpAllReferencedMem(CONTEXT * ctxt)
{
	if(!KnobPrintRecoveredMemAccesses)
		return;
	for(std::vector<Ins_MEMI>::iterator it = opbuf.rMems.begin();
			it!=opbuf.rMems.end();
			it++)
	{
		logfile(6)<<"DUMP TSC:"
			<<global_tsc
			<<" RMEM @ "
			<<hex<<(*it).address<<dec<<" ";
		DumpReg(ctxt,REG_RIP,6);
	}
	for(std::vector<Ins_MEMI>::iterator it = opbuf.wMems.begin();
			it!=opbuf.wMems.end();
			it++)
	{
		logfile(6)<<"DUMP TSC:"
			<<global_tsc
			<<" WMEM @ "
			<<hex<<(*it).address<<dec<<" ";
		DumpReg(ctxt,REG_RIP,6);
	}
}

/*
 * Collect register/memory status
 * --------------------
 * setup goal first
 * then collect them all
 * analyse usage at the end<tryFinalize>
 */

VOID tryFinalize(CONTEXT * ctxt)
{
	/*
	 * available vector
	 */
	BOOL ins_input_reg_req = false;//is register input required
	BOOL ins_input_mem_req = false;//is memory input required
	BOOL ins_input_reg_av = false;//is register input available
	BOOL ins_input_mem_av =  true;//is memory input available
	//
	//BOOL ins_output_to_reg = false;//is register is an output destination
	BOOL ins_output_to_mem = false;//is register is an output destination

	if(opbuf.rRegs.size()!=opbuf.rRegCnt)
	{
		return;
	}
	if(opbuf.wRegs.size()!=opbuf.wRegCnt)
	{
		return;
	}
	if((opbuf.rMems.size()+opbuf.wMems.size())!=opbuf.rwMemCnt)
	{
		return;
	}
	
	ins_count++;

	logfile(0)<<" * Finalize"<<endl;

	ins_input_mem_req = (opbuf.rMems.size()!=0);
	ins_output_to_mem = (opbuf.wMems.size()!=0);
	ins_input_reg_req = (opbuf.rRegs.size()!=0);
	//ins_output_to_reg = (opbuf.wRegs.size()!=0);

	//////////////////////////
	//FIXME: Memory Operation!
	// how can I know the content in the memory is good?

	if(ins_input_mem_req || ins_output_to_mem)
	{
		ins_memop_count++;
	}

	/*
	 * Inspect the following criterion
	 * -----------
	 * - read mem/regs are not affected
	 * - if all read mem/regs are available, write mem/regs are available
	 * - if any read mem/regs are NA, write mem/regs are NA
	 */

	//related read register
	for(std::vector<REG>::iterator it = opbuf.rRegs.begin();
			it!=opbuf.rRegs.end();
			it++)
	{
		logfile(1)<<"REG:"<<REG_StringShort(*it)<<" is ";
		if(!GetREGAVM(*it,_avm))
		{
			logfile(1)<<"0"<<endl;
			ins_input_reg_av = false;
			goto na_handler;
			break;
		}else
		{
			ins_input_reg_av = true;
			logfile(1)<<"1"<<endl;
		}
	}
	//related read memory
	for(std::vector<Ins_MEMI>::iterator it = opbuf.rMems.begin();
			it!=opbuf.rMems.end();
			it++)
	{
#if _USE_MMM_
		//FIXME!
		logfile(2)<<"test rMEM @ "<<hex<<(*it).address<<dec;
		//search mm list
		list<ADDRINT*>::iterator xit = find(mm.begin(),mm.end(),(*it).address);
		if(xit==mm.end())
		{
			logfile(2)<<" NA "<<endl;
			ins_input_mem_av = false;
			goto na_handler;
		}
		//do real copy test
		EXCEPTION_INFO exptInfo;
		ADDRINT value;
		if(PIN_SafeCopyEx(&value, (*it).address, (*it).size, &exptInfo)!=(*it).size)
		{
			logfile(4)<<" Exception:"<<PIN_ExceptionToString(&exptInfo)<<endl;
		}else
		{
			logfile(2)<<" OK "<<endl;
		}
#else
		/*
		 * DO NOT TRUST MEMORY CONTENT
		 */
		ins_input_reg_av = false;
		goto na_handler;
#endif
	}


na_handler:

	//check if there exists a matching BWAS entry
	SetupRegsOrBrDestFromFile(ctxt, true, true, false);

	/////////////////////////////////////////////////////////////////////////////////
	//don't know how to deal with memop
	//should do table lookup and see whether a source mem is really available
	//should be done in : related read memory FIXME
	//////////////////////////////////////////////////////////////////////////////////
	//TODO: refactor to use automata
	//
	//if any input required is not available,
	//this instruction can not be executed
	//
	//
	//NOTE: for x86, if memory address is calculated,
	// then it must be calculated by using registers,
	// if all registers are available, then all memory addresses are available.
	// but the content in that address may be invaild in our case
	if(ins_input_reg_req^ins_input_reg_av) 
	{
		ins_skip_count++;
		//if it is an memory instruction, 
		//increase the counter
		if(ins_input_mem_req||ins_output_to_mem)
		{
			ins_memop_skip_count++;
		}
		//set all target mem and all related registers NA
		//////////////
		logfile(1)<<"Required Registers NA, jmp to nextip:"<<hex<<opbuf.nextip<<dec<<endl;
		SetAllTgtNA(ctxt);

		PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&opbuf.nextip) );
		PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&opbuf.nextip) );
		PIN_ExecuteAt(ctxt);
	}
#if 1
	else if(ins_input_mem_req)
	{
		//FIXME:caution! the content at reading memory address may be invalid
		//just skip that instruction

		//the address is valid, dump the address
		dumpAllReferencedMem(ctxt);

		if(ins_input_mem_av)
		{
			logfile(1)<<"Input has memory address, but avilable, speculative execute";
			SetAllTgtAvailable();
		}else
		{
			//set all target invalid, for we don't know whether the content at
			//memory address is valid or not
			logfile(1)<<"Input memory NA, jmp to nextip:"<<hex<<opbuf.nextip<<dec<<endl;
			SetAllTgtNA(ctxt);

			PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&opbuf.nextip) );
			PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&opbuf.nextip) );
			//SetupRegsOrBrDestFromFile(ctxt,true);
			PIN_ExecuteAt(ctxt);
		}
	}
#endif
	else if(ins_output_to_mem)
	{
		//FIXME: caution! the memory for output may not allocated
		//FIXME: emulate memory write, record the content to somewhere else
		//FIXME: need an emulator to produce the output
		//instructions like:
		//	push %rbp
		//		Read Register: %rbp, %rsp
		//		Write Register: %rsp
		//		Write memory: [%rsp]

		//the address is valid, dump the address
		dumpAllReferencedMem(ctxt);
	
#if 1
		logfile(2)<<"Input require only register file, but output to mem, try execute it."<<endl;
		//handle potential memory exceptions???
		for(std::vector<Ins_MEMI>::iterator it = opbuf.wMems.begin();
			it!=opbuf.wMems.end();
			it++)
		{
			logfile(2)<<"test wMEM @ "<<hex<<(*it).address<<dec;
			EXCEPTION_INFO exptInfo;
			ADDRINT value;
			if(PIN_SafeCopyEx(&value, (*it).address, (*it).size, &exptInfo)!=(*it).size)
			{
				logfile(4)<<" Exception:"<<PIN_ExceptionToString(&exptInfo)<<endl;
				/*
				 * if an exception happens, that means we can not
				 * execute this instruction, we should skip to next
				 * instruction
				 */
				logfile(4)<<" skip this instruction"<<endl;
				SetAllTgtNA(ctxt);
				PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&opbuf.nextip) );
				PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&opbuf.nextip) );
				PIN_ExecuteAt(ctxt);
			}else
			{
				logfile(2)<<" OK "<<endl;
			}
#if _USE_MMM_
			//remove fixed address from mm NA list
			list<ADDRINT*>::iterator xit = find(mm.begin(),mm.end(),(*it).address);
			if(xit==mm.end())
			{
				logfile(2)<<"add "<<hex<<(*it).address<<dec<<" to mm"<<endl;
				mm.push_back((*it).address);
			}
#endif
		}
		//registers
		SetAllTgtAvailable();
#else
		logfile(1)<<"Output has memory address, jmp to nextip:"<<hex<<opbuf.nextip<<dec<<endl;
		SetAllTgtNA(ctxt);

		PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&opbuf.nextip) );
		PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&opbuf.nextip) );
		//SetupRegsOrBrDestFromFile(ctxt,true);
		PIN_ExecuteAt(ctxt);
#endif
	}else// no memory required for input and output
	{
		//FIXME:caution!
		// the content at reading memory address may be invalid
		// the memory address planed to write to may be not allocated
		//
		// if only require registers and registers are available
		//  and 
		//registers
		
		//the address is valid, dump the address
		dumpAllReferencedMem(ctxt);

		SetAllTgtAvailable();
		logfile(2)<<"Other case. try execute it."<<endl;
	}
}

VOID SetupCollector(CONTEXT * ctxt,
		UINT32 ReadRegCnt,
		UINT32 WriteRegCnt,
		UINT32 MemCnt,
		ADDRINT nextip)
{
	if(!beginLog) return;
	PIN_REGISTER tgtreg;
	PIN_GetContextRegval( ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&tgtreg));

	opbuf.ip = tgtreg;

	opbuf.nextip = nextip;

	opbuf.rRegCnt = ReadRegCnt;
	opbuf.wRegCnt = WriteRegCnt;
	opbuf.rwMemCnt = MemCnt;

	opbuf.rRegs.clear();
	opbuf.wRegs.clear();
	opbuf.rMems.clear();
	opbuf.wMems.clear();

	/////////
	logfile(1)<<"SetupCollector"
		<<"(IP:"<<dr(ctxt, REG_INST_PTR)<<"):"
		<<ReadRegCnt<<"/"
		<<WriteRegCnt<<"/"
		<<MemCnt<<" "
		<<endl;
	tryFinalize(ctxt);
}

VOID recRRegUsage(CONTEXT * ctxt,
		REG ReadRegId)
{
	if(!beginLog) return;
	logfile(1)<<" - ReadRegId: "
		<<REG_StringShort(ReadRegId)
		<<":"<<ReadRegId
		<<endl;
	opbuf.rRegs.push_back(ReadRegId);
	tryFinalize(ctxt);
}

VOID recWRegUsage(CONTEXT * ctxt,
		REG WriteRegId)
{
	if(!beginLog) return;
	logfile(1)<<" - WriteRegId: "
		<<REG_StringShort(WriteRegId)
		<<":"<<WriteRegId
		<<endl;
	opbuf.wRegs.push_back(WriteRegId);
	tryFinalize(ctxt);
}

VOID recRMemUsage(CONTEXT * ctxt,
		ADDRINT * ReadMemAddr,
		UINT32 rsize)
{
	if(!beginLog) return;
	logfile(1)<<" - ReadMemAddr: "
		<<hex<<ReadMemAddr<<dec
		<<" ("<<rsize<<"b)"
		<<endl;
	Ins_MEMI t=
	{
		ReadMemAddr,rsize
	};
	opbuf.rMems.push_back(t);
	tryFinalize(ctxt);
}

VOID recWMemUsage(CONTEXT * ctxt,
		ADDRINT * WriteMemAddr,
		UINT32 wsize)
{
	if(!beginLog) return;
	logfile(1)<<" - WriteMemAddr: "
		<<hex<<WriteMemAddr<<dec
		<<" ("<<wsize<<"b)"
		<<endl;
	Ins_MEMI t=
	{
		WriteMemAddr,wsize
	};
	opbuf.wMems.push_back(t);
	tryFinalize(ctxt);
}
#if 0
///////////////////////////////////////////////////////////////////////////////
//instruction with rep, nrep prefix
//if rcx is available then we can execute,
//otherwise skip this instruction
VOID inspectRepInstruction(CONTEXT * ctxt)
{
	
}
/////////////////////////////////////////////////////////////////////////////////////////////////////
#endif

/*
 * dump IP Address for backward slice
 */
VOID dumpIP(CONTEXT * ctxt)
{
	if(beginLog)
	{
		logfile(5)<<"BackwardSlice IP:";
		DumpReg(ctxt,REG_RIP,5);
	}
}

VOID Instruction(INS ins, VOID *v)
{
	//record currentip and its preceeding ip
	ipmap[INS_Address(ins)] = INS_NextAddress(ins);
	//logfile(0)<<"ip:"<<hex<<INS_Address(ins)<<"->"<<INS_NextAddress(ins)<<endl;

	if(beginLog)
	{
		void *addr = Addrint2VoidStar(INS_Address(ins));
		logfile(0)<<"("<<addr<<")=>disass:"<<INS_Disassemble(ins)<<endl;
	}
	////////////////////////////////
	//inspect ip address of executed instruction
	if(KnobPrintStraightLineCode)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dumpIP, IARG_CONTEXT, IARG_END);
	}
	////////////////////////////////
	//immediately return if target ip is not in main image
	ADDRINT ins_ip = INS_Address(ins);
	if((ins_ip>mainImageHighAddress) || (ins_ip<mainImageLowAddress))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)guideRet, IARG_CONTEXT, IARG_END);
	}
	////////////////////////////////
	if(INS_IsBranch(ins))
	{
		if(beginLog) logfile(0)<<"IsBranch"<<endl;
		INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)guideBranch,
				IARG_CONTEXT,
				IARG_PTR,
				INS_Address(ins),
				IARG_PTR,
				INS_NextAddress(ins),
				IARG_END);
	}else if(INS_IsCall(ins))
	{
		if(INS_IsDirectCall(ins))
		{
			if(beginLog) logfile(0)<<"IsDirectCall"<<endl;
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)guideDirectCall,
					IARG_CONTEXT,
					IARG_PTR,
					INS_Address(ins),
					IARG_PTR,
					INS_NextAddress(ins),
					IARG_PTR,
					INS_DirectBranchOrCallTargetAddress(ins),
					IARG_END);
		}else
		{
			if(beginLog) logfile(0)<<"IsIndirectCall"<<endl;
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)guideIndirectCall,
					IARG_CONTEXT,
					IARG_PTR,
					INS_Address(ins),
					IARG_PTR,
					INS_NextAddress(ins),
					IARG_END);
		}
	}else if(INS_IsRet(ins))
	{
		if(beginLog) logfile(0)<<"IsRet"<<endl;
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)guideRet, IARG_CONTEXT, IARG_END);
	}else if(INS_IsSyscall(ins))
	{
		if(beginLog) logfile(0)<<"IsSystemCall"<<endl;
		INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)guideSyscall,
				IARG_CONTEXT,
				IARG_SYSCALL_NUMBER,
				IARG_PTR,
				INS_NextAddress(ins),
				IARG_END);
	}else if(INS_IsInterrupt(ins))
	{
		//skip int
		//skip repne
		//skip rep
		INS_Delete(ins);
	}/*else if(INS_RepnePrefix(ins) || INS_RepPrefix(ins))
	{
		INS_InsertCall(ins, 
				IPOINT_BEFORE,
				(AFUNPTR)inspectRepInstruction,
				IARG_CONTEXT,
				IARG_END);
	}*/
	else
	{
		if(beginLog) logfile(0)<<"IsOther"<<endl;

/////////////////////////////////////////////////////////////////////////////////////
#if 0
//emulator
//only for memory operation
		switch(INS_Opcode(ins))
		{
			case(XED_ICLASS_PUSH):
				break;
			case(XED_ICLASS_POP):
				break;
			case(XED_ICLASS_MOV):
				break;
			case(XED_ICLASSS_SUB):
				break;
		}
#endif
/////////////////////////////////////////////////////////////////////////////////////



		int regRcnt = INS_MaxNumRRegs(ins);
		int regWcnt = INS_MaxNumWRegs(ins);
		int memRWcnt = INS_MemoryOperandCount(ins);
		//some operator is rw, need to fix
		int fixedmemRWcnt = 0;
		for(int memOp=0;memOp<memRWcnt;memOp++)
		{
			if(INS_MemoryOperandIsWritten(ins,memOp))
			{
				fixedmemRWcnt++;
			}
			if(INS_MemoryOperandIsRead(ins,memOp))
			{
				fixedmemRWcnt++;
			}
		}

		//NOTE: deal with predicate instruction,
		//eg. cmova, cmovb
		//we do not use INS_InsertPredicatedCall
		INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)SetupCollector,
				IARG_CONTEXT,
				IARG_UINT32,
				regRcnt,
				IARG_UINT32,
				regWcnt,
				IARG_UINT32,
				fixedmemRWcnt,
				IARG_PTR,
				INS_NextAddress(ins),
				IARG_END);

		/*
		 * register read
		 */
		for(int i=0;i<regRcnt;i++)
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)recRRegUsage,
					IARG_CONTEXT,
					IARG_UINT32,
					INS_RegR(ins, i),
					IARG_END);
		}
		/*
		 * register write
		 */
		for(int i=0;i<regWcnt;i++)
		{
			INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)recWRegUsage,
					IARG_CONTEXT,
					IARG_UINT32,
					INS_RegW(ins, i),
					IARG_END);
		}
		/*
		 * memory read/write
		 */
		for(int memOp=0;memOp<memRWcnt;memOp++)
		{
			if(INS_MemoryOperandIsRead(ins,memOp))
			{
				INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)recRMemUsage,
						IARG_CONTEXT,
						IARG_MEMORYOP_EA,
						memOp,
						IARG_UINT32,
						INS_MemoryReadSize(ins),
						IARG_END
						);
			}
			if(INS_MemoryOperandIsWritten(ins,memOp))
			{
				INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)recWMemUsage,
						IARG_CONTEXT,
						IARG_MEMORYOP_EA,
						memOp,
						IARG_UINT32,
						INS_MemoryWriteSize(ins),
						IARG_END
						);
			}
		}
	}

	return;
}

// Print the list of images currently loaded, with some information about each.
#if 0
static VOID PrintImageList()
{
    for (IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        string imageName = IMG_Name(img);
        //ADDRESS_RANGE range = FindImageTextMargin(img);

        //fprintf (stderr, "   L  %-40s [0x%llx:0x%llx] offset 0x%llx %4d RTNs\n", imageName.c_str(),
        //         (unsigned long long)range._low, (unsigned long long)range._high, (unsigned long long)IMG_LoadOffset(img),
        //           CountImageRtns (img));
	logfile(6)<<"IMG: "<<IMG_Name(img)<<" is loaded @ "<<hex<<IMG_LoadOffset(img)<<dec<<endl;
    }    
}
#endif
/*
 * instrument main for switching on guided execution
 */
VOID instrumentMainSwitch(RTN rtn, VOID *v)
{
#if 0
//////////////////
//DEBUG!
	PrintImageList();
//////////////////
#endif
	//logfile(6)<<"RTN:"<<RTN_Name(rtn)<<endl;
	if(RTN_Name(rtn)!="main")
		return;
	logfile(6)<<"Found main RTN"<<endl;
	RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SwitchOnGuide, IARG_CONTEXT, IARG_END);
	RTN_Close(rtn);
	PIN_LockClient();
	IMG image = IMG_FindByAddress(RTN_Address(rtn));
	if(IMG_IsMainExecutable(image))
	{
		mainImageLowAddress = IMG_LowAddress(image);
		mainImageHighAddress = IMG_HighAddress(image);
		logfile(6)<<"Main executable mapped from: "
			<<"0x"<<hex<<mainImageLowAddress<<dec
			<<" To "
			<<"0x"<<hex<<mainImageHighAddress<<dec
			<<endl;
	}
	PIN_UnlockClient();

}

/*
 * load the shared library memory according to layout file.
 * otherwise, let miniloader load the shared library by itself
 */

static BOOL LoadSharedLibrary()
{
	dylibmapfile.open(KnobDylibmmapFile.Value().c_str());
	
	if(!dylibmapfile.is_open())
	{
		//no memory layout file is provided
		return false;
	}
	PIN_SetReplayMode (REPLAY_MODE_IMAGEOPS);
	PIN_LockClient();
	
	string imgName;
	string fileName;
	ADDRINT loadOffset;

	int imgcnt = 0;

	while(!dylibmapfile.eof())
	{
		if(!(dylibmapfile>>imgName))
			break;
		if(!(dylibmapfile>>fileName))
			break;
		if(!(dylibmapfile>>hex>>loadOffset))
			break;

		logfile(6)<<"Deterministic Dynamic Loader, Setup IMG:"
			<<imgName 
			<<" => "
			<<fileName
			<<" @ "
			<<hex<<loadOffset<<dec
			<<endl;

		PIN_ReplayImageLoad(imgName.c_str(),
			fileName.c_str(),
			loadOffset,
			imgcnt==0?REPLAY_IMAGE_TYPE_MAIN_EXE:REPLAY_IMAGE_TYPE_REGULAR);
		imgcnt++;
	}
	dylibmapfile.close();
	PIN_UnlockClient();
	return true;
}

static VOID ImgLoad(IMG img, VOID * v)
{
	//signal(SIGSEGV, sig_die);
	logfile(5)
		<< "Loading "
		<< IMG_Name(img)
		<< "@"
		<< hex<<IMG_LoadOffset(img)<<dec
		<< ", Image id = "
		<< IMG_Id(img)
		<< " Type:"
		<< IMG_Type(img)
		<< endl;
}


//////////////////////////////////////////////////////////////////////////
//Signal handler
//FIXME!: the trace is not consective, pt trace is subject to lost,
//that means when we encounter several SIGSEGV event, we need to restart from the middle of the trace
//
/*
 * SIGSEGV
 */
BOOL SIGSEGV_Handler(THREADID tid,
		INT32 sig,
		CONTEXT *ctxt,
		BOOL hasHandler,
		const EXCEPTION_INFO *pExceptInfo,
		VOID *v)
{
	logfile(5)<<"Program received SIGSEGV @ ";
	DumpReg(ctxt, REG_INST_PTR, 5);
	logfile(5)<<" Exception:"<<PIN_ExceptionToString(pExceptInfo)<<endl;
	for(int i=0;i<TOTAL_REGS;i++)
		DumpReg(ctxt, regSeq[i], 0);
	logfile(5)<<"Ignoring SIGSEGV"<<endl;
	//char mfbuf[256];
	//sprintf(mfbuf,"cat /proc/%d/maps",PIN_GetPid());
	//logfile(5)<<"maps:"<<mfbuf<<endl;
	//if(system(mfbuf)){};//make gcc happy
	//skip to nextip

	ADDRINT currentip;
	PIN_GetContextRegval( ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&currentip));
	ADDRINT nextip = ipmap[currentip];
	if(nextip==0)//nothing???
	{
		logfile(5)<<"We are lost, restarting."<<endl;
		//load new context and return here
		//PIN_ExecuteAt should not be called from a callback
		restart_execution(ctxt, false, true);
	}else
	{
		logfile(5)<<"Skipping to nextip:0x"<<hex<<nextip<<dec<<endl;

		PIN_SetContextRegval(ctxt, REG_INST_PTR, reinterpret_cast<UINT8*>(&nextip) );
		PIN_SetContextRegval(ctxt, REG_RIP, reinterpret_cast<UINT8*>(&nextip) );
	}

	//make involved Memory location NA
	//TODO: may be we should store the correct data somewhere else?
	
	return false;
}

BOOL SIGILL_Handler(THREADID tid,
		INT32 sig,
		CONTEXT *ctxt,
		BOOL hasHandler,
		const EXCEPTION_INFO *pExceptInfo,
		VOID *v)
{
	logfile(5)<<"Program received SIGILL @ ";
	DumpReg(ctxt, REG_INST_PTR, 5);
	logfile(5)<<" Exception:"<<PIN_ExceptionToString(pExceptInfo)<<endl;
	for(int i=0;i<TOTAL_REGS;i++)
		DumpReg(ctxt, regSeq[i], 0);
	logfile(5)<<"Ignoring SIGILL"<<endl;

	logfile(5)<<"Restarting."<<endl;
	//load new context and return here
	//PIN_ExecuteAt should not be called from a callback
	restart_execution(ctxt, false, true);

	return false;
}
///////////////////////////////////////////////////////////////////////////

VOID ImageUnload(IMG img, VOID *v)
{
	logfile(5) << "Unloading " << IMG_Name(img) << endl;
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	logfile(4)<<"Finish."<<endl;
	ReportStat(true);
	_logfile.close();
}
#if 0
/*
 * signal handler
 * dump file offset when dying
 */
void sig_die(int signum)
{
	if(infile.is_open())
	{
		logfile(8)
			<<"DIE fp("
			<<KnobInputFile.Value().c_str()
			<<")@"
			<<infile.tellg()
			<<endl;
		infile.close();
	}
}
#endif

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

	srand(time(NULL));

	INITIALIZE_RXCTXT;

	infile.open(KnobInputFile.Value().c_str());
	_logfile.open(KnobOutputFile.Value().c_str());

	provided_dylib_map = LoadSharedLibrary();
	
	if(infile.is_open())
	{
		IMG_AddInstrumentFunction(ImgLoad, 0);
		beginLog = false;
		//detect input file type
		int t;
		infile>>t;
		infiletype = (t==0)?INPUT_PTPIN:INPUT_PERF;
		if(infiletype==INPUT_PTPIN)
		{
			logfile(3)<<"input type : PTPIN"<<endl;
		}else if(infiletype==INPUT_PERF)
		{
			logfile(3)<<"input type : PERF"<<endl;
		}
	}


	INS_AddInstrumentFunction(Instruction, 0);
	PIN_InterceptSignal(SIGSEGV,SIGSEGV_Handler,0);
	PIN_InterceptSignal(SIGILL,SIGILL_Handler,0);
	IMG_AddUnloadFunction(ImageUnload, 0);

	RTN_AddInstrumentFunction(instrumentMainSwitch,0);

	PIN_AddFiniFunction(Fini, 0);
	//signal(SIGSEGV, sig_die);
	// Never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
