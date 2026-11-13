import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA
import joblib
import warnings
warnings.filterwarnings('ignore')

class EnhancedIPAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.kmeans = None
        self.gmm = None
        self.label_encoders = {}
        self.optimal_clusters = 5
        self.feature_columns = []
        
    def load_and_preprocess_data(self, file_path):
        """Load and preprocess the dataset with all columns"""
        try:
            df = pd.read_csv(file_path)
            print(f"Dataset loaded successfully! Shape: {df.shape}")
        except FileNotFoundError:
            print("Dataset file not found!")
            return None
        
        # Convert datetime
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        
        # Fix latitude and longitude values
        df['latitude'] = pd.to_numeric(df['latitude'], errors='coerce')
        df['longitude'] = pd.to_numeric(df['longitude'], errors='coerce')
        
        # Ensure valid latitude/longitude ranges
        df['latitude'] = df['latitude'].apply(lambda x: x if -90 <= x <= 90 else np.nan)
        df['longitude'] = df['longitude'].apply(lambda x: x if -180 <= x <= 180 else np.nan)
        
        # Basic info
        print("\nDataset info:")
        print(f"Time range: {df['datetime'].min()} to {df['datetime'].max()}")
        print(f"Unique source IPs: {df['src'].nunique()}")
        print(f"Unique countries: {df['country'].nunique()}")
        print(f"Missing latitude values: {df['latitude'].isna().sum()}")
        print(f"Missing longitude values: {df['longitude'].isna().sum()}")
        
        return df.dropna(subset=['src', 'datetime'])
    
    def extract_advanced_features(self, df):
        """Extract comprehensive features using all available columns"""
        print("Extracting advanced features...")
        
        # Group by source IP to create aggregated features
        ip_features = df.groupby('src').agg({
            'datetime': ['count', 'nunique', 'min', 'max'],  # Attack patterns
            'dpt': ['nunique', lambda x: x.mode()[0] if not x.mode().empty else -1],  # Port usage
            'spt': 'nunique',  # Source port variety
            'proto': 'nunique',  # Protocol variety
            'type': 'nunique',  # Attack type variety
            'host': 'nunique',  # Target variety
            'cc': 'first',  # Country code
            'country': 'first',  # Country name
            'latitude': 'mean',  # Average latitude
            'longitude': 'mean',  # Average longitude
            'locale': 'first'  # Location details
        }).reset_index()
        
        # Flatten column names
        ip_features.columns = [
            'IP', 'Total_Attacks', 'Unique_Days', 'First_Attack', 'Last_Attack',
            'Unique_Dest_Ports', 'Most_Common_Port', 'Unique_Src_Ports',
            'Unique_Protocols', 'Unique_Attack_Types', 'Unique_Hosts',
            'Country_Code', 'Country_Name', 'Latitude', 'Longitude', 'Locale'
        ]
        
        # Calculate additional temporal features
        ip_features['Attack_Duration_Days'] = (
            ip_features['Last_Attack'] - ip_features['First_Attack']
        ).dt.total_seconds() / 86400
        
        ip_features['Attacks_Per_Day'] = ip_features['Total_Attacks'] / np.maximum(
            ip_features['Attack_Duration_Days'], 1
        )
        
        # Convert IP to numerical features
        ip_features[['Octet1', 'Octet2', 'Octet3', 'Octet4']] = ip_features['IP'].apply(
            lambda ip: pd.Series(self.ip_to_octets(ip))
        )
        
        # Calculate geolocation features (simplified without geopy)
        # Use fixed reference point (New York)
        ref_lat, ref_lon = 40.7128, -74.0060
        
        def calculate_distance(lat, lon):
            if pd.isna(lat) or pd.isna(lon):
                return 10000  # Default large distance for missing values
            
            # Simple haversine approximation (good enough for relative distances)
            lat_diff = abs(lat - ref_lat)
            lon_diff = abs(lon - ref_lon)
            distance_km = np.sqrt(lat_diff**2 + lon_diff**2) * 111  # Approx 111km per degree
            return distance_km
        
        ip_features['Distance_From_Ref_KM'] = ip_features.apply(
            lambda row: calculate_distance(row['Latitude'], row['Longitude']), axis=1
        )
        
        # Time-based features
        ip_features['Attack_Time_Variance'] = df.groupby('src')['datetime'].apply(
            lambda x: x.dt.hour.std() if len(x) > 1 and x.dt.hour.std() > 0 else 0
        ).values
        
        # Protocol-specific attack counts
        for proto in df['proto'].unique():
            if pd.notna(proto):
                proto_counts = df[df['proto'] == proto].groupby('src').size()
                ip_features[f'Attacks_{proto}'] = ip_features['IP'].map(proto_counts).fillna(0)
        
        # Port range analysis
        ip_features['Common_Ports_Ratio'] = ip_features['Most_Common_Port'].apply(
            lambda x: 1 if x in [80, 443, 22, 21, 25, 53, 110, 143, 993, 995] else 0
        )
        
        # Fill NaN values
        ip_features = ip_features.fillna({
            'Latitude': 0,
            'Longitude': 0,
            'Distance_From_Ref_KM': 10000,
            'Attack_Time_Variance': 0,
            'Attack_Duration_Days': 1,
            'Attacks_Per_Day': 0
        })
        
        print(f"Extracted {len(ip_features.columns)} features for {len(ip_features)} unique IPs")
        return ip_features
    
    def ip_to_octets(self, ip):
        """Convert IP address to octets"""
        try:
            octets = list(map(int, str(ip).split('.')))
            if len(octets) == 4:
                return octets
        except:
            pass
        return [0, 0, 0, 0]
    
    def prepare_training_data(self, ip_features_df):
        """Prepare features for model training"""
        # Select numerical features
        numerical_features = [
            'Total_Attacks', 'Unique_Days', 'Unique_Dest_Ports', 'Unique_Src_Ports',
            'Unique_Protocols', 'Unique_Attack_Types', 'Unique_Hosts',
            'Attack_Duration_Days', 'Attacks_Per_Day', 'Distance_From_Ref_KM',
            'Attack_Time_Variance', 'Common_Ports_Ratio',
            'Octet1', 'Octet2', 'Octet3', 'Octet4'
        ]
        
        # Add protocol-specific features
        protocol_features = [col for col in ip_features_df.columns if col.startswith('Attacks_')]
        numerical_features.extend(protocol_features)
        
        # Keep only existing columns
        numerical_features = [col for col in numerical_features if col in ip_features_df.columns]
        
        X = ip_features_df[numerical_features].fillna(0).values
        self.feature_columns = numerical_features
        
        print(f"Using {len(numerical_features)} features for training")
        return X
    
    def train_models(self, df):
        """Train both K-means and GMM models with advanced features"""
        # Extract features
        ip_features_df = self.extract_advanced_features(df)
        X = self.prepare_training_data(ip_features_df)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Determine optimal clusters
        self.find_optimal_clusters(X_scaled)
        
        # Train K-means
        print("Training K-means model...")
        self.kmeans = KMeans(n_clusters=self.optimal_clusters, random_state=42, n_init=10)
        kmeans_labels = self.kmeans.fit_predict(X_scaled)
        
        # Train GMM
        print("Training Gaussian Mixture Model...")
        self.gmm = GaussianMixture(n_components=self.optimal_clusters, random_state=42)
        gmm_labels = self.gmm.fit_predict(X_scaled)
        
        # Calculate anomaly thresholds
        kmeans_scores = self.calculate_anomaly_scores(X_scaled, self.kmeans.cluster_centers_, kmeans_labels)
        gmm_probs = self.gmm.predict_proba(X_scaled)
        gmm_scores = -np.log(np.max(gmm_probs, axis=1) + 1e-10)
        
        self.kmeans_threshold = np.percentile(kmeans_scores, 95)
        self.gmm_threshold = np.percentile(gmm_scores, 95)
        
        print(f"K-means anomaly threshold: {self.kmeans_threshold:.4f}")
        print(f"GMM anomaly threshold: {self.gmm_threshold:.4f}")
        
        return ip_features_df, X_scaled, kmeans_labels, gmm_labels
    
    def find_optimal_clusters(self, data, max_clusters=8):
        """Find optimal number of clusters using elbow method and silhouette score"""
        wcss = []
        silhouette_scores = []
        
        for i in range(2, max_clusters + 1):
            kmeans = KMeans(n_clusters=i, random_state=42, n_init=10)
            kmeans.fit(data)
            wcss.append(kmeans.inertia_)
            
            if len(data) > 10000:
                sample_indices = np.random.choice(len(data), min(10000, len(data)), replace=False)
                sample_data = data[sample_indices]
                labels_sample = kmeans.predict(sample_data)
                score = silhouette_score(sample_data, labels_sample)
            else:
                score = silhouette_score(data, kmeans.labels_)
            silhouette_scores.append(score)
        
        # Simple elbow detection
        differences = np.diff(wcss)
        self.optimal_clusters = np.argmin(differences) + 3
        
        print(f"Optimal number of clusters: {self.optimal_clusters}")
    
    def calculate_anomaly_scores(self, data, centers, labels):
        """Calculate anomaly scores based on distance from cluster centers"""
        distances = np.linalg.norm(data - centers[labels], axis=1)
        return distances
    
    def predict_single_ip(self, ip_data):
        """
        Predict if a single IP address is anomalous
        """
        if self.kmeans is None or self.gmm is None:
            raise ValueError("Models not trained. Please train models first.")
        
        # Prepare feature vector
        features = []
        for col in self.feature_columns:
            if col in ip_data:
                features.append(ip_data[col])
            else:
                features.append(0)
        
        features = np.array([features])
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict with K-means
        kmeans_cluster = self.kmeans.predict(features_scaled)[0]
        kmeans_distance = np.linalg.norm(features_scaled - self.kmeans.cluster_centers_[kmeans_cluster])
        kmeans_anomaly = kmeans_distance > self.kmeans_threshold
        
        # Predict with GMM
        gmm_probs = self.gmm.predict_proba(features_scaled)
        gmm_score = -np.log(np.max(gmm_probs) + 1e-10)
        gmm_anomaly = gmm_score > self.gmm_threshold
        gmm_cluster = self.gmm.predict(features_scaled)[0]
        
        # Calculate confidence scores
        kmeans_confidence = min(100, (kmeans_distance / self.kmeans_threshold) * 100)
        gmm_confidence = min(100, (gmm_score / self.gmm_threshold) * 100)
        
        result = {
            'ip_address': ip_data.get('IP', 'Unknown'),
            'features': ip_data,
            'kmeans': {
                'cluster': int(kmeans_cluster),
                'distance': float(kmeans_distance),
                'threshold': float(self.kmeans_threshold),
                'is_anomaly': bool(kmeans_anomaly),
                'confidence': float(kmeans_confidence)
            },
            'gmm': {
                'cluster': int(gmm_cluster),
                'score': float(gmm_score),
                'threshold': float(self.gmm_threshold),
                'is_anomaly': bool(gmm_anomaly),
                'confidence': float(gmm_confidence)
            },
            'overall_anomaly': bool(kmeans_anomaly or gmm_anomaly),
            'agreement': bool(kmeans_anomaly == gmm_anomaly)
        }
        
        return result
    
    def create_ip_data_from_input(self, user_input):
        """Create IP data dictionary from user input"""
        ip_data = {
            'IP': user_input.get('ip_address', ''),
            'Octet1': 0, 'Octet2': 0, 'Octet3': 0, 'Octet4': 0,
            'Total_Attacks': user_input.get('total_attacks', 1),
            'Unique_Dest_Ports': user_input.get('unique_dest_ports', 1),
            'Unique_Src_Ports': user_input.get('unique_src_ports', 1),
            'Unique_Protocols': user_input.get('unique_protocols', 1),
            'Unique_Attack_Types': user_input.get('unique_attack_types', 1),
            'Unique_Hosts': user_input.get('unique_hosts', 1),
            'Attack_Duration_Days': user_input.get('attack_duration_days', 1),
            'Attacks_Per_Day': user_input.get('attacks_per_day', 1),
            'Distance_From_Ref_KM': user_input.get('distance_from_ref_km', 10000),
            'Attack_Time_Variance': user_input.get('attack_time_variance', 0),
            'Common_Ports_Ratio': user_input.get('common_ports_ratio', 0)
        }
        
        # Convert IP to octets
        if 'ip_address' in user_input:
            octets = self.ip_to_octets(user_input['ip_address'])
            ip_data.update({
                'Octet1': octets[0],
                'Octet2': octets[1],
                'Octet3': octets[2],
                'Octet4': octets[3]
            })
        
        return ip_data
    
    def save_models(self, filepath):
        """Save trained models to disk"""
        joblib.dump({
            'scaler': self.scaler,
            'kmeans': self.kmeans,
            'gmm': self.gmm,
            'kmeans_threshold': self.kmeans_threshold,
            'gmm_threshold': self.gmm_threshold,
            'feature_columns': self.feature_columns
        }, filepath)
        print(f"Models saved to {filepath}")
    
    def load_models(self, filepath):
        """Load trained models from disk"""
        models = joblib.load(filepath)
        self.scaler = models['scaler']
        self.kmeans = models['kmeans']
        self.gmm = models['gmm']
        self.kmeans_threshold = models['kmeans_threshold']
        self.gmm_threshold = models['gmm_threshold']
        self.feature_columns = models['feature_columns']
        print(f"Models loaded from {filepath}")

# Simplified main function for testing
def main():
    # Initialize the detector
    detector = EnhancedIPAnomalyDetector()
    
    # Load data
    df = detector.load_and_preprocess_data('AWS_Honeypot_marx-geo.csv')
    if df is None:
        return
    
    # Train models
    print("Training models with advanced features...")
    try:
        ip_features_df, X_scaled, kmeans_labels, gmm_labels = detector.train_models(df)
        print("Models trained successfully!")
        
        # Save models
        detector.save_models('enhanced_ip_anomaly_detector.pkl')
        
        # Test prediction
        test_input = {
            'ip_address': '192.168.1.100',
            'total_attacks': 5,
            'unique_dest_ports': 2,
            'unique_src_ports': 1,
            'unique_protocols': 1,
            'unique_attack_types': 1,
            'unique_hosts': 1,
            'attack_duration_days': 1,
            'attacks_per_day': 5,
            'distance_from_ref_km': 8000,
            'attack_time_variance': 2,
            'common_ports_ratio': 0.8
        }
        
        ip_data = detector.create_ip_data_from_input(test_input)
        result = detector.predict_single_ip(ip_data)
        
        print(f"\nTest Prediction for {result['ip_address']}:")
        print(f"K-means anomaly: {result['kmeans']['is_anomaly']}")
        print(f"GMM anomaly: {result['gmm']['is_anomaly']}")
        print(f"Overall anomaly: {result['overall_anomaly']}")
        
    except Exception as e:
        print(f"Error during training: {e}")
        print("Trying with simplified features...")
        # Fallback to simpler approach if advanced features fail

def interactive_prediction():
    """Interactive prediction function"""
    detector = EnhancedIPAnomalyDetector()
    
    try:
        detector.load_models('enhanced_ip_anomaly_detector.pkl')
    except:
        print("Models not found. Please train models first.")
        return
    
    print("\n" + "="*60)
    print("IP ANOMALY DETECTION - INTERACTIVE MODE")
    print("="*60)
    
    while True:
        print("\nEnter IP details (or 'quit' to exit):")
        
        user_input = {}
        user_input['ip_address'] = input("IP Address: ")
        if user_input['ip_address'].lower() == 'quit':
            break
        
        try:
            # Get basic inputs
            user_input['total_attacks'] = int(input("Total Attacks: ") or 1)
            user_input['unique_dest_ports'] = int(input("Unique Destination Ports: ") or 1)
            user_input['unique_protocols'] = int(input("Unique Protocols: ") or 1)
            user_input['unique_attack_types'] = int(input("Unique Attack Types: ") or 1)
            
            # Set default values for other features
            user_input['unique_src_ports'] = 1
            user_input['unique_hosts'] = 1
            user_input['attack_duration_days'] = 1
            user_input['attacks_per_day'] = user_input['total_attacks']
            user_input['distance_from_ref_km'] = 10000
            user_input['attack_time_variance'] = 0
            user_input['common_ports_ratio'] = 0.5
            
            # Create IP data and predict
            ip_data = detector.create_ip_data_from_input(user_input)
            result = detector.predict_single_ip(ip_data)
            
            # Display results
            print("\n" + "="*40)
            print("PREDICTION RESULTS")
            print("="*40)
            print(f"IP Address: {result['ip_address']}")
            print(f"K-means: {'🚨 ANOMALY' if result['kmeans']['is_anomaly'] else '✅ NORMAL'} "
                  f"(Confidence: {result['kmeans']['confidence']:.1f}%)")
            print(f"GMM: {'🚨 ANOMALY' if result['gmm']['is_anomaly'] else '✅ NORMAL'} "
                  f"(Confidence: {result['gmm']['confidence']:.1f}%)")
            print(f"Overall: {'🚨 ANOMALY DETECTED' if result['overall_anomaly'] else '✅ NORMAL TRAFFIC'}")
            print("="*40)
            
        except ValueError:
            print("Please enter valid numerical values!")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
    
    # Run interactive prediction after training
    interactive_prediction()