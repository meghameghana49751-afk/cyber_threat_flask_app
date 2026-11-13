'''
This is the main function of the PE classification of this program
The library used to extract the features from the PE was pefile and you can find it here,
https://pypi.org/project/pefile/

In this program we are first extracting the features from the PE and then providing it to the saved machine and using thoses features we are prediciting whether the PE is malicious or not.
'''

import pefile
import os
import array
import math
import pickle
import joblib
import sys
import argparse
import sklearn.ensemble as ek
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import cross_val_score
import time

# NEW IMPORT FOR XGBOOST
import xgboost as xgb


#For calculating the entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy

#For extracting the resources part
def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

#For getting the version information
def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          res['os'] = pe.VS_FIXEDFILEINFO.FileOS
          res['type'] = pe.VS_FIXEDFILEINFO.FileType
          res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          res['signature'] = pe.VS_FIXEDFILEINFO.Signature
          res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

#extract the info for a given file using pefile
def extract_infos(fpath):
    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy)/float(len((entropy)))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x:x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len((raw_sizes)))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x:x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    #Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    #Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    #Resources
    resources= get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources)> 0:
        entropy = list(map(lambda x:x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x:x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0


    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res


def train_and_compare_models():
    """Train and compare XGBoost vs Random Forest"""
    print("Loading dataset...")
    dataset = pd.read_csv('data.csv', sep='|')
    
    # Feature matrix
    X = dataset.drop(['Name','md5','legitimate'],axis=1).values
    # Target variable
    y = dataset['legitimate'].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        stratify=y,
        random_state=42
    )
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    
    # Initialize models
    models = {
        'XGBoost': xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective='binary:logistic',
            eval_metric='logloss',
            n_jobs=-1,
            random_state=42
        ),
        'Random Forest': RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            n_jobs=-1,
            random_state=42
        )
    }
    
    results = {}
    train_times = {}
    
    # Train and evaluate models
    for name, model in models.items():
        print(f"\nTraining {name}...")
        start_time = time.time()
        
        # Train model
        model.fit(X_train, y_train)
        train_time = time.time() - start_time
        train_times[name] = train_time
        
        # Predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        # Cross-validation score
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
        
        results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': conf_matrix,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'y_pred': y_pred,
            'y_pred_proba': y_pred_proba,
            'train_time': train_time
        }
        
        print(f"{name} Results:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1-Score: {f1:.4f}")
        print(f"  Cross-validation Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        print(f"  Training Time: {train_time:.2f} seconds")
        print(f"  Confusion Matrix:\n{conf_matrix}")
    
    # Generate comparison plots
    generate_comparison_plots(results, train_times, y_test)
    
    # Save the best model
    best_model_name = max(results, key=lambda x: results[x]['accuracy'])
    print(f"\nBest model: {best_model_name} with accuracy: {results[best_model_name]['accuracy']:.4f}")
    
    # Save the best model
    joblib.dump(models[best_model_name], f'best_model_{best_model_name.replace(" ", "_").lower()}.pkl')
    print(f"Best model saved as 'best_model_{best_model_name.replace(' ', '_').lower()}.pkl'")
    
    return results, models


def generate_comparison_plots(results, train_times, y_test):
    """Generate comparison plots between models"""
    
    # 1. Performance Metrics Comparison
    metrics = ['accuracy', 'precision', 'recall', 'f1_score']
    models = list(results.keys())
    
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('Model Comparison: XGBoost vs Random Forest', fontsize=16, fontweight='bold')
    
    # Bar chart for metrics comparison
    ax = axes[0, 0]
    x = np.arange(len(metrics))
    width = 0.35
    
    for i, model in enumerate(models):
        values = [results[model][metric] for metric in metrics]
        ax.bar(x + i*width - width/2, values, width, label=model, alpha=0.8)
    
    ax.set_xlabel('Metrics')
    ax.set_ylabel('Score')
    ax.set_title('Performance Metrics Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for i, model in enumerate(models):
        for j, metric in enumerate(metrics):
            value = results[model][metric]
            ax.text(j + i*width - width/2, value + 0.01, f'{value:.3f}', 
                   ha='center', va='bottom', fontsize=9)
    
    # 2. Training Time Comparison
    ax = axes[0, 1]
    times = [train_times[model] for model in models]
    bars = ax.bar(models, times, color=['#1f77b4', '#ff7f0e'], alpha=0.8)
    ax.set_xlabel('Model')
    ax.set_ylabel('Training Time (seconds)')
    ax.set_title('Training Time Comparison')
    ax.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for bar, time_val in zip(bars, times):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
               f'{time_val:.2f}s', ha='center', va='bottom', fontsize=10)
    
    # 3. Cross-validation Scores
    ax = axes[0, 2]
    cv_means = [results[model]['cv_mean'] for model in models]
    cv_stds = [results[model]['cv_std'] for model in models]
    
    bars = ax.bar(models, cv_means, yerr=cv_stds, capsize=5, 
                 color=['#1f77b4', '#ff7f0e'], alpha=0.8)
    ax.set_xlabel('Model')
    ax.set_ylabel('Cross-validation Accuracy')
    ax.set_title('Cross-validation Performance (5-fold)')
    ax.grid(True, alpha=0.3)
    ax.set_ylim([min(cv_means) - 0.1, 1.0])
    
    # 4. ROC Curves
    ax = axes[1, 0]
    for model in models:
        fpr, tpr, _ = roc_curve(y_test, results[model]['y_pred_proba'])
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, lw=2, label=f'{model} (AUC = {roc_auc:.3f})')
    
    ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5)
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curves')
    ax.legend(loc="lower right")
    ax.grid(True, alpha=0.3)
    
    # 5. Confusion Matrices
    for idx, model in enumerate(models):
        ax = axes[1, 1 + idx]
        cm = results[model]['confusion_matrix']
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                   xticklabels=['Malicious', 'Legitimate'],
                   yticklabels=['Malicious', 'Legitimate'])
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title(f'Confusion Matrix - {model}')
    
    plt.tight_layout()
    plt.savefig('model_comparison.png', dpi=150, bbox_inches='tight')
    plt.show()
    
    # 6. Detailed comparison table
    print("\n" + "="*80)
    print("DETAILED MODEL COMPARISON")
    print("="*80)
    print(f"{'Metric':<20} {'XGBoost':<15} {'Random Forest':<15} {'Difference':<15}")
    print("-"*80)
    
    for metric in metrics:
        xgb_val = results['XGBoost'][metric]
        rf_val = results['Random Forest'][metric]
        diff = xgb_val - rf_val
        print(f"{metric:<20} {xgb_val:<15.4f} {rf_val:<15.4f} {diff:<+15.4f}")
    
    print(f"{'Training Time':<20} {results['XGBoost']['train_time']:<15.2f} {results['Random Forest']['train_time']:<15.2f} {results['XGBoost']['train_time'] - results['Random Forest']['train_time']:<+15.2f}")
    print("="*80)


def process_single_file(fpath):
    """Process a single PE file for prediction"""
    print(f"Processing file: {fpath}")
    
    # Extract features
    data = extract_infos(fpath)
    features=['Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionsMaxRawsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal', 'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize']
    
    pe_features = list(map(lambda x:data[x], features))
    
    # Load dataset to get feature structure
    dataset = pd.read_csv('data.csv', sep='|')
    X = dataset.drop(['Name','md5','legitimate'],axis=1).values
    
    # Load the best model
    try:
        best_model = joblib.load('best_model_xgboost.pkl')
        model_name = "XGBoost"
    except:
        try:
            best_model = joblib.load('best_model_random_forest.pkl')
            model_name = "Random Forest"
        except:
            print("No saved model found. Training new model...")
            results, models = train_and_compare_models()
            best_model_name = max(results, key=lambda x: results[x]['accuracy'])
            best_model = models[best_model_name]
            model_name = best_model_name
    
    # Make prediction
    res = best_model.predict([pe_features])[0]
    proba = best_model.predict_proba([pe_features])[0]
    
    print(f"\nPrediction using {model_name}:")
    print(f"  Result: {['Malicious', 'Legitimate'][res]}")
    print(f"  Confidence: {proba[res]:.2%}")
    print(f"  Malicious probability: {proba[1]:.2%}")
    print(f"  Legitimate probability: {proba[0]:.2%}")
    
    return ['malicious', 'legitimate'][res]


def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='PE Malware Classifier')
    parser.add_argument('--train', action='store_true', help='Train and compare models')
    parser.add_argument('--predict', type=str, help='Predict a single PE file')
    parser.add_argument('--compare', action='store_true', help='Train and compare models with visualization')
    
    args = parser.parse_args()
    
    if args.train or args.compare:
        print("Training and comparing models...")
        results, models = train_and_compare_models()
        
        if args.compare:
            print("\nComparison completed. Check 'model_comparison.png' for visualizations.")
    
    elif args.predict:
        result = process_single_file(args.predict)
        print(f"\nFinal classification: {result}")
    
    else:
        # Default: train and compare
        print("No arguments provided. Training and comparing models...")
        results, models = train_and_compare_models()


if __name__ == "__main__":
    main()